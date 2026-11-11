"""Workflow shared by the CLI and the GUI: scan -> discover -> verify -> (dry run | apply).

Where updates come from
  * a manifest signed by a key pinned in trust.py (the strongest source), and/or
  * OS-native discovery when no manifest is loaded: Microsoft Update Catalog on Windows,
    fwupd/LVFS and the distro's driver tooling on Linux (core/discovery/).

Privilege separation
  The front end runs unprivileged. `apply()` writes a plan file and starts the elevated
  helper (installer.helper_command). The helper treats the plan as untrusted input and
  decides for itself what is acceptable:
    manifest package    -> manifest signature against the pinned keys, SHA-256, publisher signature
    catalog discovery   -> pnputil only, and the package's .cat must be signed by Microsoft's
                           hardware publisher, whatever the plan says
    distro package      -> only if the helper's own run of the distro's driver tool recommends it
    fwupd device update -> fwupd verifies it against LVFS
  For every Windows driver package the helper fetches the LOLDrivers blocklist and checks each
  .sys before anything else; a hit aborts the whole plan. Then: restore point, then install.
"""
from __future__ import annotations

import dataclasses
import json
import os
import re
import secrets
import shutil
import tempfile
from pathlib import Path

from . import common, elevation, installer, manifest, restore, trust, verifier
from .common import ElevationError, InstallError, VerificationError
from .discovery import linux_lvfs, ms_catalog
from .model import Device, Update
from .security import loldrivers

MAX_PLAN_ITEMS = 64
AUTO_DISCOVER = True          # discover online when no manifest is loaded (overridden per Context)
_GUID = re.compile(r"^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$")


@dataclasses.dataclass
class Context:
    manifest: dict | None = None
    manifest_raw: bytes = b""
    signature: bytes = b""
    quarantine: Path = dataclasses.field(default_factory=lambda: common.state_dir() / "quarantine")
    allow_loopback_http: bool = False     # demo and tests only
    demo: bool = False                    # fake payloads: never installs
    discover: bool | None = None          # None: automatic (on when no manifest is loaded)
    blocklist: object = None              # session copy of the LOLDrivers feed; False = unavailable
    notes: list[str] = dataclasses.field(default_factory=list)   # non-fatal problems to show the user


def load_manifest_files(ctx: Context, manifest_path: Path, signature_path: Path) -> None:
    ctx.manifest_raw, ctx.signature = Path(manifest_path).read_bytes(), Path(signature_path).read_bytes()
    ctx.manifest = manifest.load_manifest(ctx.manifest_raw, ctx.signature)


# ------------------------------------------------------------------- scan
def scan() -> tuple[list[Device], dict[str, dict]]:
    common.audit("scan.start", os=common.OS_NAME, arch=common.ARCH)
    if common.OS_NAME == "windows":
        from . import scanner_win
        devices, upgrades = scanner_win.scan(), {}
    elif common.OS_NAME == "linux":
        from . import scanner_linux
        devices, upgrades = scanner_linux.scan()
    else:
        raise InstallError(f"{common.OS_NAME} is not supported")
    common.audit("scan.done", devices=len(devices), fwupd_upgrades=len(upgrades))
    return devices, upgrades


# -------------------------------------------------------------- discovery
def discovery_enabled(ctx: Context) -> bool:
    if ctx.demo:
        return False
    return ctx.discover if ctx.discover is not None else (AUTO_DISCOVER and ctx.manifest is None)


def discover(devices: list[Device], ctx: Context, progress=None) -> list[Update]:
    """OS-native discovery. Never raises: a failure becomes a note and an empty result."""
    updates: list[Update] = []
    try:
        if common.OS_NAME == "windows":
            from . import scanner_win
            for dev, pkg in scanner_win.discover_updates(devices, progress=progress):
                detail = "" if pkg.get("id_confirmed") else "matched by catalog search only"
                updates.append(Update(dev, pkg["name"], dev.driver_version or "unknown", pkg["version"],
                                      "Microsoft Update Catalog", "", pkg, "pending", detail))
        elif common.OS_NAME == "linux":
            recs = linux_lvfs.driver_recommendations(devices)
            for dev, rec in linux_lvfs.match_devices(recs, devices):
                updates.append(Update(dev, rec.package, dev.driver_version or dev.driver or "not installed",
                                      rec.package, f"distro ({rec.tool})", "", linux_lvfs.to_package(rec), "delegated",
                                      f"{rec.reason}; installed from the distro repository"))
    except (ms_catalog.CatalogError, VerificationError, OSError) as exc:
        ctx.notes.append(f"online discovery failed: {exc}")
        common.audit("discovery.failed", error=str(exc))
    common.audit("discovery.done", updates=len(updates))
    return updates


def find_all_updates(devices: list[Device], upgrades: dict[str, dict], ctx: Context, progress=None) -> list[Update]:
    """Manifest and fwupd updates, plus discovered ones for devices the manifest does not cover."""
    updates = manifest.find_updates(devices, ctx.manifest, upgrades)
    if discovery_enabled(ctx):
        covered = {id(u.device) for u in updates}
        updates += [u for u in discover(devices, ctx, progress) if id(u.device) not in covered]
    return updates


# ----------------------------------------------------------------- verify
def session_blocklist(ctx: Context):
    """LOLDrivers feed for the early, unprivileged check. Fetched once per session, in memory."""
    if ctx.blocklist is None:
        try:
            ctx.blocklist = loldrivers.fetch(allow_loopback_http=ctx.allow_loopback_http)
        except loldrivers.BlocklistUnavailable as exc:
            ctx.blocklist = False
            ctx.notes.append(f"LOLDrivers blocklist unavailable: {exc}")
    return ctx.blocklist or None


def _precheck_blocklist(update: Update, ctx: Context, path: Path) -> str:
    art, method = update.package["artifact"], update.package["install"]["method"]
    if method != "pnputil" or ctx.demo:
        return ""
    blocklist = session_blocklist(ctx)
    checked = loldrivers.check_archive(path, art["format"], blocklist) if blocklist else None
    if checked is None:
        return "; LOLDrivers check runs at install"
    return f"; LOLDrivers: {len(checked)} .sys file(s) clean"


def _purge(ctx: Context, sha256: str) -> None:
    for leftover in ctx.quarantine.glob(f"{sha256[:16]}-*") if sha256 else []:
        try:
            os.chmod(leftover, 0o600)
        except OSError:
            pass
        leftover.unlink(missing_ok=True)


def _verify_catalog_update(update: Update, ctx: Context, progress=None) -> None:
    pkg, art = update.package, update.package["artifact"]
    info = ms_catalog.resolve_download(pkg)
    path, digest, size = verifier.download_from_host(
        info.url, ctx.quarantine, art["filename"], host_ok=ms_catalog.is_download_host,
        max_size=ms_catalog.MAX_DRIVER_BYTES, expected_sha1=info.sha1 or None, expected_sha256=info.sha256 or None,
        allow_loopback_http=ctx.allow_loopback_http, progress=progress)
    art.update(url=info.url, sha256=digest, size=size)
    update.sha256, update.path = digest, str(path)
    update.detail = ("downloaded from Microsoft; " + ("catalog digest OK" if info.sha1 or info.sha256 else
                     "catalog published no digest") + "; Microsoft hardware-publisher signature is checked at install"
                     + _precheck_blocklist(update, ctx, path))
    update.status = "verified"


def verify_update(update: Update, ctx: Context, progress=None) -> None:
    """Download and verify one update as the ordinary user. Sets update.status; never raises."""
    art = (update.package or {}).get("artifact")
    if not art:
        return  # fwupd-managed or repository package: verified by fwupd / the package manager
    try:
        if update.package.get("origin") == "ms-catalog":
            return _verify_catalog_update(update, ctx, progress)
        sig = art["signature"]
        path = verifier.secure_download(art["url"], art["sha256"], art["size"], ctx.quarantine, art["filename"],
                                        allow_loopback_http=ctx.allow_loopback_http, progress=progress)
        sig_file = ""
        if ctx.demo:
            detail = "demo payload: publisher signature step skipped"
        else:
            if sig["type"] == "gpg":
                sig_file = str(verifier.fetch_small(sig["signature_url"], ctx.quarantine / (path.name + ".sig"),
                                                    allow_loopback_http=ctx.allow_loopback_http))
            detail = verifier.verify_publisher(update.package, path, sig_file)
        detail += _precheck_blocklist(update, ctx, path)
        update.status, update.detail = "verified", "SHA-256 OK; " + detail
        update.path, update.signature_file = str(path), sig_file
    except (VerificationError, ms_catalog.CatalogError) as exc:
        _purge(ctx, update.sha256 or art.get("sha256", ""))   # also when a later check fails after the hash passed
        update.status, update.detail, update.path = "failed", f"{exc} - file purged", ""


def ready(updates: list[Update]) -> list[Update]:
    return [u for u in updates if u.status in ("verified", "delegated")]


def update_key(u: Update) -> str:
    return u.package["id"] if u.package else f"fwupd:{u.device.address}"


# ---------------------------------------------------------------- dry run
def dry_run_plan(updates: list[Update]) -> list[str]:
    """What apply() would do, as text. Runs nothing and needs no privileges."""
    todo = ready(updates)
    if not todo:
        return ["Nothing verified, nothing to apply."]
    lines = []
    if any(u.package and u.package["install"]["method"] == "pnputil" for u in todo):
        lines.append("[elevated] fetch the LOLDrivers blocklist and check every .sys; any match aborts everything")
    snap = restore.create(dry_run=True)
    lines.append(f"[elevated] {snap.detail}" if snap.tool else
                 f"!! {snap.detail}; the install would proceed with a warning" if common.OS_NAME == "linux"
                 else f"!! {snap.detail}")
    for u in todo:
        try:
            res = (installer.install_fwupd_device(u.device.address) if u.package is None
                   else installer.install(u.package, Path(u.path) if u.path else None))
            lines += ["[elevated] " + " ".join(c) for c in res.commands]
        except InstallError as exc:
            lines.append(f"!! {u.name}: {exc}")
        if u.package and u.package["install"].get("reboot_required"):
            lines.append(f"   restart required after {u.name}")
    common.audit("apply.dry_run", plan=lines)
    return lines


# ------------------------------------------------------------------ apply
def write_plan(updates: list[Update], ctx: Context, allow_without_snapshot: bool = False,
               allow_without_blocklist: bool = False) -> tuple[Path, str]:
    plan_id = secrets.token_hex(16)
    plan_dir = common.state_dir() / "plans" / plan_id
    plan_dir.mkdir(parents=True)
    items = []
    for u in updates:
        if u.package is None:
            items.append({"fwupd_device": u.device.address})
        elif u.package.get("origin"):
            items.append({"discovered": u.package, "file": u.path})
        else:
            items.append({"package_id": u.package["id"], "file": u.path, "signature_file": u.signature_file})
    (plan_dir / "manifest.json").write_bytes(ctx.manifest_raw)
    (plan_dir / "manifest.json.sig").write_bytes(ctx.signature)
    plan = {"plan_id": plan_id, "manifest": str(plan_dir / "manifest.json"),
            "signature": str(plan_dir / "manifest.json.sig"),
            "allow_without_snapshot": bool(allow_without_snapshot),
            "allow_without_blocklist": bool(allow_without_blocklist), "items": items}
    path = plan_dir / "plan.json"
    path.write_text(json.dumps(plan, indent=1))
    return path, plan_id


def helper_argv(plan_path: Path) -> list[str]:
    return installer.helper_command(plan_path)


def apply(updates: list[Update], ctx: Context, *, allow_without_snapshot: bool = False,
          allow_without_blocklist: bool = False) -> dict:
    """Install the verified updates for real. Requests elevation if the process is not elevated."""
    todo = ready(updates)
    if not todo:
        return {"status": "nothing", "detail": "nothing verified, nothing to apply", "items": []}
    if ctx.demo:
        raise InstallError("demo mode never installs anything")
    plan_path, plan_id = write_plan(todo, ctx, allow_without_snapshot, allow_without_blocklist)
    common.audit("apply.requested", plan=plan_id, items=len(todo), already_elevated=elevation.is_admin())
    if elevation.is_admin():
        result = execute_plan(plan_path)
    else:
        rc = elevation.run_elevated(helper_argv(plan_path))
        try:
            result = json.loads((common.system_state_dir() / "results" / f"{plan_id}.json").read_text())
        except (OSError, ValueError):
            result = {"status": "failed", "items": [],
                      "detail": f"the elevated helper exited with code {rc} and left no result"}
    if result.get("status") == "security_alert":            # purge the offending download on our side too
        for u in todo:
            if update_key(u) in (result.get("alerts") or []):
                _purge(ctx, u.sha256)
                u.status, u.detail, u.path = "failed", result.get("detail", "blocked") + " - file purged", ""
    common.audit("apply.result", plan=plan_id, status=result.get("status"))
    return result


# --------------------------------------------------------- elevated helper
def _read_capped(path, limit: int) -> bytes:
    with open(path, "rb") as fh:
        data = fh.read(limit + 1)
    if len(data) > limit:
        raise VerificationError(f"{path} is larger than expected")
    return data


def _staging_dir() -> Path:
    """A directory only administrators can write to, for the helper's verified copies."""
    path = Path(tempfile.mkdtemp(prefix="safedriver-stage-"))
    if common.OS_NAME == "windows":
        # Drop inherited ACEs; full control for Administrators and SYSTEM only.
        res = common.run(["icacls", str(path), "/inheritance:r", "/grant:r",
                          "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F"])
        if res is None or res.rc != 0:
            shutil.rmtree(path, ignore_errors=True)
            raise InstallError("could not lock down the staging directory")
    return path


def _item_record(ident: str, name: str, res: installer.InstallResult) -> dict:
    return {"id": ident, "name": name, "status": res.status, "rc": res.rc, "detail": res.detail,
            "commands": res.commands}


def _policy_catalog_package(desc) -> dict:
    """Rebuild a catalog-discovered package from the few fields the helper accepts. Method,
    format and the required signer are fixed here; the plan cannot choose them."""
    if common.OS_NAME != "windows":
        raise VerificationError("catalog driver packages can only be installed on Windows")
    art = desc.get("artifact") if isinstance(desc, dict) else None
    update_id = str(desc.get("update_id", "")) if isinstance(desc, dict) else ""
    if not _GUID.match(update_id) or not isinstance(art, dict):
        raise VerificationError("malformed discovered package")
    sha256, size = str(art.get("sha256", "")), art.get("size")
    if not manifest.SHA256_RE.match(sha256) or not isinstance(size, int) or not 0 < size <= ms_catalog.MAX_DRIVER_BYTES:
        raise VerificationError("discovered package was not downloaded and hashed")
    return {"id": f"mscatalog.{update_id}", "origin": "ms-catalog", "name": str(desc.get("name") or update_id)[:200],
            "version": str(desc.get("version") or "0")[:64],
            "artifact": {"filename": f"{update_id}.cab", "size": size, "sha256": sha256, "format": "cab",
                         "signature": {"type": "authenticode", "target": "catalog", "subject": trust.MS_WHQL_SUBJECT}},
            "install": {"method": "pnputil", "reboot_required": False}}


def _policy_repo_package(desc) -> dict:
    """A distro package is installed only if the helper's own run of the distro's driver
    tooling recommends it for this hardware; the name in the plan is merely a request."""
    if common.OS_NAME != "linux":
        raise VerificationError("distribution packages can only be installed on Linux")
    name = str(((desc or {}).get("install") or {}).get("package_name", "")) if isinstance(desc, dict) else ""
    if not linux_lvfs.PACKAGE_NAME.match(name):
        raise VerificationError("malformed package name")
    from . import scanner_linux
    rec = linux_lvfs.recommended_packages(scanner_linux.scan_pci()).get(name)
    if rec is None:
        raise VerificationError(f"{name} is not a driver package this distribution recommends for this hardware")
    return {"id": f"distro.{name}", "origin": "linux-repo", "name": name, "version": "0",
            "install": {"method": "package-manager", "package_name": name, "manager": rec.manager,
                        "reboot_required": True}}


def _resolve(item, man) -> tuple[str, str, dict | None]:
    """(kind, name, package) for one plan item, or raise. No files are touched here."""
    if "fwupd_device" in item:
        installer.fwupd_device_command(str(item["fwupd_device"]))          # validates the id
        return "fwupd", "fwupd device update", None
    if "discovered" in item:
        desc = item["discovered"]
        origin = desc.get("origin") if isinstance(desc, dict) else None
        if origin == "ms-catalog":
            pkg = _policy_catalog_package(desc)
        elif origin == "linux-repo":
            pkg = _policy_repo_package(desc)
        else:
            raise VerificationError("unknown discovery origin")
        return "pkg", pkg["name"], pkg
    pkg = manifest.package_by_id(man, str(item.get("package_id"))) if man else None
    if pkg is None:
        raise VerificationError("not in the signed manifest")
    if not manifest.applies_to_platform(pkg):
        raise VerificationError("not for this platform")
    return "pkg", pkg["name"], pkg


def _ident(item) -> str:
    if not isinstance(item, dict):
        return "?"
    if isinstance(item.get("discovered"), dict):
        return str(item["discovered"].get("id") or "discovered")
    return str(item.get("package_id") or ("fwupd:" + str(item.get("fwupd_device"))))


def _refuse(result: dict, ident: str, reason: str) -> None:
    common.audit("helper.refused", item=ident, reason=reason)
    result["items"].append({"id": ident, "name": ident, "status": "refused", "rc": -1, "detail": reason,
                            "commands": []})


def _run_plan(plan: dict, result: dict, trusted_keys) -> None:
    items = plan.get("items")
    if not isinstance(items, list) or not 0 < len(items) <= MAX_PLAN_ITEMS:
        raise VerificationError("plan has no items or too many")
    man = None
    if any(isinstance(i, dict) and "package_id" in i for i in items):
        man = manifest.load_manifest(_read_capped(plan["manifest"], manifest.MAX_MANIFEST_BYTES),
                                     _read_capped(plan["signature"], 4096), trusted_keys=trusted_keys,
                                     seq_dir=common.system_state_dir())

    # 1. Decide what each item is, by the helper's own rules.
    resolved = []
    for item in items:
        ident = _ident(item)
        try:
            kind, name, pkg = _resolve(item, man)
            resolved.append((kind, ident, name, pkg, item))
        except (VerificationError, InstallError, OSError, KeyError, TypeError, AttributeError) as exc:
            _refuse(result, ident, str(exc))

    # 2. Live BYOVD blocklist, fetched now, only if a Windows driver package is involved.
    blocklist = None
    if any(pkg and pkg["install"]["method"] == "pnputil" for _, _, _, pkg, _ in resolved):
        try:
            blocklist = loldrivers.fetch()
        except loldrivers.BlocklistUnavailable as exc:
            if plan.get("allow_without_blocklist") is not True:
                result.update(status="blocklist_unavailable",
                              detail=f"the LOLDrivers blocklist could not be loaded: {exc}. Nothing was installed.")
                return
            common.audit("blocklist.skipped", reason=str(exc), authorised_by="user")
            result["blocklist"] = "skipped at the user's request"

    staging = _staging_dir()
    try:
        # 3. Private copy, hash, publisher signature, unpack, blocklist, catalog signer.
        prepared = []  # (kind, ident, name, pkg, install_command)
        for kind, ident, name, pkg, item in resolved:
            try:
                if kind == "fwupd":
                    prepared.append((kind, str(item["fwupd_device"]), name, None, None))
                    continue
                staged = None
                art = pkg.get("artifact")
                if art:
                    staged = verifier.stage_verified_copy(Path(str(item["file"])), staging, art["sha256"],
                                                          art["size"], art["filename"])
                    sig_copy = None
                    if art["signature"]["type"] == "gpg":
                        sig_copy = staging / (staged.name + ".sig")
                        sig_copy.write_bytes(_read_capped(str(item["signature_file"]), 1 << 16))
                    verifier.verify_publisher(pkg, staged, str(sig_copy) if sig_copy else None)
                prepared.append((kind, ident, name, pkg, installer.prepare(pkg, staged, staging, blocklist)))
            except loldrivers.SecurityAlert as alert:
                # A known vulnerable or malicious driver: abort the whole plan, install nothing.
                result["items"] = [i for i in result["items"] if i["status"] == "refused"]
                _refuse(result, ident, str(alert))
                result.update(status="security_alert", detail=str(alert), alerts=[ident], matches=alert.matches)
                return
            except (VerificationError, InstallError, OSError, KeyError, TypeError) as exc:
                _refuse(result, ident, str(exc))
        if not prepared:
            result.update(status="refused", detail="no item passed verification; nothing was installed")
            return

        # 4. Restore point.
        snap = restore.create()
        result["snapshot"] = dataclasses.asdict(snap)
        if not snap.ok:
            required = any(p and p["install"].get("snapshot_required") for _, _, _, p, _ in prepared)
            tolerated = plan.get("allow_without_snapshot") is True or (
                snap.status == "unavailable" and common.OS_NAME == "linux")  # Linux, no tool: warn and continue
            if required or not tolerated:
                result.update(status="snapshot_failed", snapshot_required=bool(required),
                              detail=f"no restore point: {snap.detail}. Nothing was installed.")
                return

        # 5. Install.
        for kind, ident, name, pkg, command in prepared:
            res = (installer.install_fwupd_device(ident, dry_run=False) if kind == "fwupd"
                   else installer.execute(pkg, command))
            result["items"].append(_item_record(f"fwupd:{ident}" if kind == "fwupd" else ident, name, res))
        good = [i for i in result["items"] if i["status"] in ("installed", "reboot-required", "no-op")]
        result["status"] = "ok" if len(good) == len(result["items"]) else "partial" if good else "failed"
        result["reboot_required"] = any(i["status"] == "reboot-required" for i in result["items"])
    finally:
        shutil.rmtree(staging, ignore_errors=True)      # staged copies and unpacked drivers are always purged


def execute_plan(plan_path: Path, *, trusted_keys: dict | None = None) -> dict:
    """Entry point of the elevated helper. Everything in the plan is untrusted input."""
    if not elevation.is_admin():
        raise ElevationError("the install helper must run with administrator rights")
    result = {"plan_id": "", "status": "failed", "detail": "", "snapshot": None, "items": []}
    try:
        plan = json.loads(_read_capped(plan_path, 1 << 20))
        plan_id = str(plan.get("plan_id", "")) if isinstance(plan, dict) else ""
        if not re.fullmatch(r"[0-9a-f]{32}", plan_id):
            raise VerificationError("plan id is malformed")
        result["plan_id"] = plan_id
        common.audit("helper.start", plan=plan_id, items=len(plan.get("items") or []))
        _run_plan(plan, result, trusted_keys)
    except (VerificationError, InstallError, OSError, ValueError, KeyError) as exc:
        result.update(status="refused", detail=str(exc))
    common.audit("helper.done", plan=result["plan_id"], status=result["status"], detail=result["detail"])
    if result["plan_id"]:
        out = common.system_state_dir() / "results"
        out.mkdir(parents=True, exist_ok=True)
        target = out / f"{result['plan_id']}.json"
        target.write_text(json.dumps(result, indent=1))
        if os.name != "nt":
            os.chmod(out, 0o755)
            os.chmod(target, 0o644)
    return result
