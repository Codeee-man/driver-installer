#!/usr/bin/env python3
"""SafeDriver command line (driver-installer).

    driver-installer scan   [--json]                 hardware vs. manifest
    driver-installer check  [--notify] [--quiet]     exit 0 = up to date, 1 = updates available, 2+ = error
    driver-installer update --all                    download, verify, print the plan (DRY RUN)
    driver-installer update --all --apply [-y]       ...then confirm, elevate and install
    driver-installer update ID [ID ...] --apply      only the named packages
    driver-installer gui [--demo]
    driver-installer verify-log

Nothing is installed without --apply. With --apply, -y/--yes skips the
confirmation for unattended runs.

Sources of updates: a manifest (--manifest file or https URL, or
/etc/driver-installer/manifest.json) signed by a key pinned in core/trust.py;
and, when no manifest is loaded, automatic discovery: Microsoft Update Catalog
on Windows (sends hardware IDs to Microsoft), fwupd/LVFS and the distro's
driver tool on Linux. --no-discover turns discovery off, --discover forces it
on next to a manifest.

Every Windows driver package is checked against the LOLDrivers blocklist of
known vulnerable and malicious drivers before it is installed (exit code 6 on
a match).

The older flag spellings (--scan, --update-all, --gui, --verify-log) still work.
"""
from __future__ import annotations

import argparse
import dataclasses
import html
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from core import common, engine, manifest, verifier  # noqa: E402
from core.common import (EXIT_ELEVATION, EXIT_FAILED, EXIT_NOT_CONFIRMED, EXIT_OK, EXIT_REFUSED,  # noqa: E402,F401
                         EXIT_SNAPSHOT, ElevationError, InstallError, VerificationError)

CHECK_UP_TO_DATE, CHECK_UPDATES_AVAILABLE, CHECK_REFUSED, CHECK_ERROR = 0, 1, 2, 3
_LEGACY = {"--scan": ["scan"], "--update-all": ["update", "--all"], "--gui": ["gui"], "--verify-log": ["verify-log"]}


def default_manifest() -> Path:
    if common.OS_NAME == "windows":
        return common.system_state_dir() / "manifest.json"
    return Path("/etc/driver-installer/manifest.json")


def build_parser() -> argparse.ArgumentParser:
    shared = argparse.ArgumentParser(add_help=False)
    shared.add_argument("--manifest", help="manifest file or https URL (default: %s if it exists)" % default_manifest())
    shared.add_argument("--sig", help="detached manifest signature (default: <manifest>.sig)")
    shared.add_argument("--json", action="store_true", help="machine-readable output")
    shared.add_argument("--log", type=Path, help="audit log path")
    shared.add_argument("--wmi-fixture", type=Path, help="use saved WMI JSON instead of scanning this machine")
    online = shared.add_mutually_exclusive_group()
    online.add_argument("--discover", action="store_true", default=None,
                        help="search OS-native sources online even when a manifest is loaded")
    online.add_argument("--no-discover", dest="discover", action="store_false",
                        help="never search online; use only the manifest (and fwupd's local view)")

    ap = argparse.ArgumentParser(prog="driver-installer", description=f"{common.APP} {common.VERSION}")
    ap.add_argument("--version", action="version", version=f"{common.APP} {common.VERSION}")
    sub = ap.add_subparsers(dest="command", required=True, metavar="{scan,check,update,gui,verify-log}")

    sub.add_parser("scan", parents=[shared], help="list hardware, installed versions and available updates")

    check = sub.add_parser("check", parents=[shared],
                           help="exit 0 if up to date, 1 if updates are available, 2 or more on error")
    check.add_argument("--notify", action="store_true", help="desktop notification (notify-send) if updates exist")
    check.add_argument("--quiet", "-q", action="store_true", help="print nothing when up to date")

    update = sub.add_parser("update", parents=[shared], help="download and verify updates; install with --apply")
    update.add_argument("ids", nargs="*", metavar="ID", help="package ids to update (see `scan --json`)")
    update.add_argument("--all", action="store_true", help="every available update")
    how = update.add_mutually_exclusive_group()
    how.add_argument("--dry-run", action="store_true", help="show what would be done (this is the default)")
    how.add_argument("--apply", action="store_true", help="really install; requests administrator rights")
    update.add_argument("-y", "--yes", action="store_true", help="with --apply: do not ask for confirmation")
    update.add_argument("--allow-no-snapshot", action="store_true",
                        help="with --apply: continue if no restore point can be created")
    update.add_argument("--skip-blocklist", action="store_true",
                        help="with --apply: continue if the LOLDrivers blocklist cannot be downloaded")
    update.add_argument("--demo", action="store_true", help="fake local manifest with one tampered package")

    gui = sub.add_parser("gui", parents=[shared], help="open the graphical interface")
    gui.add_argument("--demo", action="store_true", help="fake local manifest with one tampered package")
    gui.add_argument("--screenshot", help=argparse.SUPPRESS)

    sub.add_parser("verify-log", parents=[shared], help="check the audit log hash chain")
    return ap


def translate_legacy(argv: list[str]) -> list[str]:
    for flag, replacement in _LEGACY.items():
        if flag in argv:
            return replacement + [a for a in argv if a != flag]
    return argv


# ------------------------------------------------------------------ inputs
def fetch_manifest(url: str, sig_url: str | None) -> tuple[Path, Path]:
    """Download manifest + signature. Safe to fetch from anywhere: it is only used if the
    pinned-key signature verifies."""
    cache = common.state_dir() / "manifest-cache"
    cache.mkdir(parents=True, exist_ok=True)
    mpath = verifier.fetch_small(url, cache / "manifest.json", limit=manifest.MAX_MANIFEST_BYTES)
    spath = verifier.fetch_small(sig_url or url + ".sig", cache / "manifest.json.sig", limit=4096)
    return mpath, spath


def load_context(args) -> engine.Context:
    ctx = engine.Context(demo=getattr(args, "demo", False), discover=args.discover)
    source = args.manifest or (str(default_manifest()) if default_manifest().exists() else None)
    if not source or ctx.demo:
        return ctx
    if source.startswith(("https://", "http://")):
        mpath, spath = fetch_manifest(source, args.sig)
    else:
        mpath, spath = Path(source), Path(args.sig or source + ".sig")
    engine.load_manifest_files(ctx, mpath, spath)
    return ctx


def inventory(args):
    if args.wmi_fixture:
        from core import scanner_win
        return scanner_win.scan(scanner_win.FixtureWmiSource(args.wmi_fixture)), {}
    return engine.scan()


def update_id(u) -> str:
    return engine.update_key(u)


def find_updates(args, ctx, devices, upgrades):
    """Manifest + fwupd + (when enabled) online discovery. Discovery problems are reported, not fatal."""
    if engine.discovery_enabled(ctx) and not args.json and not getattr(args, "quiet", False):
        print("Looking for updates (Microsoft Update Catalog)..." if common.OS_NAME == "windows"
              else "Looking for updates (fwupd, distro driver tools)...", file=sys.stderr)
    updates = engine.find_all_updates(devices, upgrades, ctx)
    for note in ctx.notes:
        print(f"note: {note}", file=sys.stderr)
    ctx.notes.clear()
    return updates


def update_record(u) -> dict:
    return {"id": update_id(u), "name": u.name, "device": u.device.name, "installed": u.installed,
            "available": u.available, "source": u.source, "sha256": u.sha256, "status": u.status,
            "detail": u.detail, "package": u.package and u.package["id"]}


# ------------------------------------------------------------------ output
def table(headers: list[str], rows: list[list[str]], widths: list[int]) -> str:
    def line(cells):
        return " | ".join(str(c)[:w].ljust(w) for c, w in zip(cells, widths)).rstrip()
    rule = "-+-".join("-" * w for w in widths)
    return "\n".join([line(headers), rule, *(line(r) for r in rows)])


def print_scan(devices, updates, have_manifest: bool) -> None:
    pending = {id(u.device) for u in updates}
    rows = [[u.device.name, u.installed or "-", u.available, "UPDATE", update_id(u)] for u in updates]
    for d in devices:
        if id(d) not in pending:
            state = "; ".join(d.notes) if d.notes else ("up to date" if have_manifest and d.driver_version else "-")
            rows.append([d.name, d.driver_version or "-", "-", state, d.hardware_ids[0] if d.hardware_ids else "-"])
    print(table(["DEVICE", "INSTALLED", "AVAILABLE", "STATUS", "ID"], rows, [44, 24, 16, 30, 40]))
    print(f"\n{len(devices)} devices, {len(updates)} update(s) available."
          + ("" if have_manifest else " No manifest loaded."))


def print_updates(updates) -> None:
    if not updates:
        print("No updates offered.")
    for u in updates:
        print(f"- {u.name}  [{update_id(u)}]\n    {u.installed} -> {u.available}   [{u.source}]\n"
              f"    sha256 {u.sha256 or '-'}\n    {u.status}{': ' + u.detail if u.detail else ''}")


def print_result(result: dict) -> None:
    snap = result.get("snapshot")
    if snap:
        print(f"Restore point: {snap['status']} {('(' + snap['tool'] + ')') if snap['tool'] else ''} {snap['detail']}")
    for item in result.get("items", []):
        print(f"- {item['name']}: {item['status']}" + (f" - {item['detail']}" if item.get("detail") else ""))
    if result.get("detail"):
        print(result["detail"])
    if result.get("reboot_required"):
        print("Restart the computer to finish.")


def notify(updates) -> bool:
    """Desktop notification through notify-send. Returns False when it could not be shown."""
    if common.OS_NAME != "linux" or not common.have("notify-send"):
        common.audit("notify.unavailable")
        return False
    names = [html.escape(u.name) for u in updates[:5]] + ([f"and {len(updates) - 5} more"] if len(updates) > 5 else [])
    title = f"{len(updates)} driver/firmware update{'s' if len(updates) != 1 else ''} available"
    body = "\n".join(names) + "\nRun: driver-installer update --all"
    res = common.run(["notify-send", "--app-name", common.APP, "--icon", "software-update-available",
                      "--", title, body], timeout=30)
    return bool(res and res.rc == 0)


def confirm(prompt: str, expected: str) -> bool:
    if not sys.stdin.isatty():
        return False
    try:
        return input(prompt).strip().lower() == expected
    except EOFError:
        return False


# ---------------------------------------------------------------- commands
def cmd_scan(args) -> int:
    ctx = load_context(args)
    devices, upgrades = inventory(args)
    updates = find_updates(args, ctx, devices, upgrades)
    if args.json:
        print(json.dumps({"devices": [dataclasses.asdict(d) for d in devices],
                          "updates": [update_record(u) for u in updates]}, indent=1))
    else:
        print_scan(devices, updates, ctx.manifest is not None)
    return EXIT_OK


def cmd_check(args) -> int:
    ctx = load_context(args)
    devices, upgrades = inventory(args)
    updates = find_updates(args, ctx, devices, upgrades)
    if args.json:
        print(json.dumps({"status": "updates-available" if updates else "up-to-date",
                          "updates": [update_record(u) for u in updates]}, indent=1))
    elif updates:
        print(f"{len(updates)} update(s) available:")
        for u in updates:
            print(f"  {u.name}: {u.installed} -> {u.available}  [{update_id(u)}]")
    elif not args.quiet:
        print("Up to date.")
    if updates and args.notify:
        notify(updates)
    return CHECK_UPDATES_AVAILABLE if updates else CHECK_UP_TO_DATE


def apply_updates(updates, ctx, args) -> int:
    todo = engine.ready(updates)
    if not todo:
        print("Nothing verified, nothing to install.")
        return EXIT_OK
    print(f"\nAbout to install {len(todo)} update(s) with administrator rights:")
    for u in todo:
        print(f"  - {u.name}  {u.installed} -> {u.available}")
    if not args.yes and not confirm("Type 'install' to proceed: ", "install"):
        print("Not confirmed; nothing was installed. (Use -y/--yes for unattended runs.)")
        return EXIT_NOT_CONFIRMED
    no_snapshot, no_blocklist = args.allow_no_snapshot, args.skip_blocklist
    result = engine.apply(todo, ctx, allow_without_snapshot=no_snapshot, allow_without_blocklist=no_blocklist)
    for _ in range(2):          # each missing safeguard needs its own explicit "yes"
        if result["status"] == "blocklist_unavailable":
            print(result["detail"])
            if not confirm("Continue WITHOUT the vulnerable-driver (LOLDrivers) check? [y/N] ", "y"):
                break
            no_blocklist = True
        elif result["status"] == "snapshot_failed" and not result.get("snapshot_required"):
            print(result["detail"])
            if not confirm("Continue WITHOUT a restore point? [y/N] ", "y"):
                break
            no_snapshot = True
        else:
            break
        result = engine.apply(todo, ctx, allow_without_snapshot=no_snapshot, allow_without_blocklist=no_blocklist)
    if result["status"] == "security_alert":
        print("\n" + "!" * 78 + f"\n{result['detail']}\nNothing was installed. The downloaded package was deleted.\n"
              + "!" * 78, file=sys.stderr)
    print_result(result)
    return common.RESULT_EXIT.get(result["status"], EXIT_FAILED)


def cmd_update(args, parser) -> int:
    if not args.all and not args.ids:
        parser.error("update: name the package ids to update, or pass --all")
    if args.apply and args.demo:
        parser.error("--demo never installs; drop --apply")
    with tempfile.TemporaryDirectory(prefix="safedriver-demo-") as tmp:
        ctx = load_context(args)
        devices, upgrades = inventory(args)
        if args.demo:
            import demo
            ctx = demo.build(devices, Path(tmp))
        updates = find_updates(args, ctx, devices, upgrades)
        if not args.all:
            known = {update_id(u) for u in updates}
            unknown = [i for i in args.ids if i not in known]
            if unknown:
                print(f"No such update: {', '.join(unknown)}. Available: {', '.join(sorted(known)) or 'none'}",
                      file=sys.stderr)
                return EXIT_REFUSED
            updates = [u for u in updates if update_id(u) in args.ids]
        for u in updates:
            engine.verify_update(u, ctx)
        failed = any(u.status == "failed" for u in updates)
        if args.json and not args.apply:
            print(json.dumps({"mode": "dry-run", "plan": engine.dry_run_plan(updates),
                              "updates": [update_record(u) for u in updates]}, indent=1))
            return EXIT_FAILED if failed else EXIT_OK
        print_updates(updates)
        if args.apply:
            return apply_updates(updates, ctx, args) or (EXIT_FAILED if failed else EXIT_OK)
        print("\nDRY RUN - nothing was installed." + (" -y has no effect without --apply." if args.yes else "")
              + " With --apply this would run:")
        print("\n".join("  " + line for line in engine.dry_run_plan(updates)))
        return EXIT_FAILED if failed else EXIT_OK


def cmd_gui(args) -> int:
    import gui
    with tempfile.TemporaryDirectory(prefix="safedriver-demo-") as tmp:
        return gui.run(load_context(args), Path(tmp), args.screenshot)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(translate_legacy(list(sys.argv[1:] if argv is None else argv)))
    if args.command == "verify-log":
        path = args.log or common.state_dir() / "audit.jsonl"
        ok, msg = common.AuditLog.verify_chain(path)
        print(f"{path}: {msg}")
        return EXIT_OK if ok else EXIT_FAILED
    reporting = args.command in ("scan", "check")       # their exit codes: 2 = refused, 3 = other error
    common.init_audit(args.log)
    common.audit("session.start", version=common.VERSION, command=args.command)
    try:
        if args.command == "scan":
            return cmd_scan(args)
        if args.command == "check":
            return cmd_check(args)
        if args.command == "update":
            return cmd_update(args, parser)
        return cmd_gui(args)
    except VerificationError as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return CHECK_REFUSED if reporting else EXIT_REFUSED
    except ElevationError as exc:
        print(f"Administrator rights were not granted: {exc}. Nothing was installed.", file=sys.stderr)
        return EXIT_ELEVATION
    except (InstallError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return CHECK_ERROR if reporting else EXIT_FAILED
    finally:
        common.audit("session.end")


if __name__ == "__main__":
    sys.exit(main())
