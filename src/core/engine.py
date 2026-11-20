"""Workflow shared by the CLI and the GUI: scan -> discover -> verify -> (dry run | apply).

Where updates come from
  * a manifest signed by a key pinned in trust.py (the strongest source), and/or
  * OS-native discovery when no manifest is loaded: Microsoft Update Catalog on Windows,
    fwupd/LVFS and the distro's driver tooling on Linux (core/discovery/).

Privilege separation
  The front end runs unprivileged. `apply()` writes a plan file and starts the elevated
  helper (elevation.helper_command). The helper treats the plan as untrusted input and
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
from .model import CHECK_ORDER, CHECK_SHORT, FAILED, NOT_APPLICABLE, PASSED, SKIPPED, Device, Update, compare_versions
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
    blocklist_error: str = ""             # why the feed is unavailable, for the check record
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


def discover(devices: list[Device], ctx: Context, *, phase=None, on_start=None, on_device=None) -> list[Update]:
    """OS-native discovery. Never raises: a failure becomes a note and an empty result.

    Callbacks, all optional, for front ends that show results while the search runs:
      phase(text, per_device)   what is running; per_device False = one search for the whole PC
      on_start(device)          this device's own lookup starts
      on_device(device, ups)    this device's result is final (ups may be []); a device not in
                                `devices` can appear (Linux "This computer")
    Devices never passed to on_device have no result from this function."""
    updates: list[Update] = []
    phase = phase or (lambda text, per_device: None)
    on_device = on_device or (lambda device, ups: None)
    try:
        if common.OS_NAME == "windows":
            updates += _discover_windows(devices, ctx, phase, on_start, on_device)
        elif common.OS_NAME == "linux":
            phase("Asking the distribution's driver tools…", False)
            recs = linux_lvfs.driver_recommendations(devices)
            by_device: dict[int, tuple[Device, list[Update]]] = {}
            for dev, rec in linux_lvfs.match_devices(recs, devices):
                update = Update(dev, rec.package, dev.driver_version or dev.driver or "not installed",
                                rec.package, f"distro ({rec.tool})", "", linux_lvfs.to_package(rec), "delegated",
                                f"{rec.reason}; installed from the distro repository")
                updates.append(update)
                by_device.setdefault(id(dev), (dev, []))[1].append(update)
            for dev, ups in by_device.values():
                on_device(dev, ups)
    except (ms_catalog.CatalogError, VerificationError, OSError) as exc:
        ctx.notes.append(f"online discovery failed: {exc}")
        common.audit("discovery.failed", error=str(exc))
    common.audit("discovery.done", updates=len(updates))
    return updates


WINDOWS_SOURCES = {"windows-update": "Windows Update", "ms-catalog": "Microsoft Update Catalog"}
CATALOG_ORIGINS = tuple(WINDOWS_SOURCES)


def _windows_update(dev: Device, pkg: dict) -> Update:
    detail = "" if pkg.get("id_confirmed") else "matched by catalog search only"
    return Update(dev, pkg["name"], dev.driver_version or "unknown", pkg["version"],
                  WINDOWS_SOURCES[pkg["origin"]], "", pkg, "pending", detail)


def _discover_windows(devices: list[Device], ctx: Context, phase, on_start, on_device) -> list[Update]:
    """Windows Update (what Windows itself offers this PC) plus the Microsoft Update Catalog
    (searched by hardware ID). One failing does not stop the other; per device the newer
    driver wins, Windows Update on a tie. Windows Update is one search for the whole PC, so it
    runs first; each device's result is then final as soon as its catalog lookup is."""
    from . import scanner_win
    from .discovery import windows_update
    best: dict[int, tuple[Device, dict]] = {}
    updates: list[Update] = []
    finished: set[int] = set()

    def offer(dev: Device, pkg: dict) -> None:
        current = best.get(id(dev))
        if current is None or compare_versions(pkg["version"], current[1]["version"]) > 0:
            best[id(dev)] = (dev, pkg)

    def finish(dev: Device) -> None:
        if id(dev) in finished:
            return
        finished.add(id(dev))
        chosen = best.get(id(dev))
        ups = [_windows_update(dev, chosen[1])] if chosen else []
        updates.extend(ups)
        on_device(dev, ups)

    def answered(dev: Device, pkg: dict | None) -> None:
        if pkg:
            offer(dev, pkg)
        finish(dev)

    wua_count = cat_count = 0
    phase("Asking Windows Update which drivers it offers this PC…", False)
    try:
        found, notes = windows_update.discover(devices)
        wua_count = len(found)
        for dev, pkg in found:
            offer(dev, pkg)
        if not found:
            ctx.notes.extend(notes)
    except windows_update.WindowsUpdateError as exc:
        ctx.notes.append(f"Windows Update search failed: {exc}")
        common.audit("wua.failed", error=str(exc))
    phase("Microsoft Update Catalog", True)
    try:
        found = scanner_win.discover_updates(devices, progress=on_start, on_result=answered)
        cat_count = len(found)
        for dev, pkg in found:               # also when a source returns without calling back
            if id(dev) not in finished:
                offer(dev, pkg)
    except ms_catalog.CatalogError as exc:
        ctx.notes.append(f"Microsoft Update Catalog search failed: {exc}")
        common.audit("catalog.failed", error=str(exc))
    for dev in devices:                      # catalog unreachable: Windows Update's answer is final
        finish(dev)
    common.audit("discovery.windows", windows_update=wua_count, catalog=cat_count, chosen=len(best))
    return updates


def find_all_updates(devices: list[Device], upgrades: dict[str, dict], ctx: Context, *,
                     progress=None, on_start=None, on_device=None) -> list[Update]:
    """Manifest and fwupd updates, plus discovered ones for devices the manifest does not cover.

    For progressive front ends (all optional):
      on_device(device, updates)  once per device, as soon as its result is final; updates may
                                  be [] (up to date). Manifest/fwupd devices come first.
      on_start(device)            a device's own online lookup begins
      progress(text, done, total) devices finished so far; total 0 = one search for the whole
                                  PC is running, progress cannot be counted per device
    """
    notify = on_device or (lambda device, ups: None)
    report = progress or (lambda text, done, total: None)
    updates = manifest.find_updates(devices, ctx.manifest, upgrades)
    covered: dict[int, list[Update]] = {}
    for u in updates:
        covered.setdefault(id(u.device), []).append(u)
    known = {id(d) for d in devices}
    final: set[int] = set()
    state = {"text": "Looking for updates", "per_device": True}

    def tick() -> None:
        report(state["text"], len(final), len(devices) if state["per_device"] else 0)

    def settle(dev: Device, ups: list[Update]) -> None:
        if id(dev) in known:
            if id(dev) in final:
                return
            final.add(id(dev))
        notify(dev, ups)
        tick()

    def phase(text: str, per_device: bool) -> None:
        state.update(text=text, per_device=per_device)
        tick()

    for dev in devices:
        if id(dev) in covered:
            settle(dev, covered[id(dev)])
    if discovery_enabled(ctx):
        def discovered(dev: Device, ups: list[Update]) -> None:
            if id(dev) not in covered:
                updates.extend(ups)
                settle(dev, ups)
        discover(devices, ctx, phase=phase, on_start=on_start, on_device=discovered)
    state["per_device"] = True
    for dev in devices:
        settle(dev, [])
    return updates


# ----------------------------------------------------------------- verify
# Each update gets one record per check (model.CHECK_ORDER) with a plain-language reason, so
# front ends can show exactly what was verified. "not_applicable" means another component
# owns that check (fwupd, the package manager) or it does not apply to this kind of package;
# "skipped" means it applies but could not be done here, which front ends show as "Partial".

def session_blocklist(ctx: Context):
    """LOLDrivers feed for the early, unprivileged check. Fetched once per session, in memory."""
    if ctx.blocklist is None:
        try:
            ctx.blocklist = loldrivers.fetch(allow_loopback_http=ctx.allow_loopback_http)
        except loldrivers.BlocklistUnavailable as exc:
            ctx.blocklist = False
            ctx.blocklist_error = str(exc)
            ctx.notes.append(f"LOLDrivers blocklist unavailable: {exc}")
    return ctx.blocklist or None


def _purge(ctx: Context, sha256: str) -> None:
    for leftover in ctx.quarantine.glob(f"{sha256[:16]}-*") if sha256 else []:
        try:
            os.chmod(leftover, 0o600)
        except OSError:
            pass
        leftover.unlink(missing_ok=True)


_NOT_YET = "not checked yet"


def _record_delegated(update: Update) -> None:
    """Updates whose verification belongs to fwupd or the package manager."""
    pkg = update.package
    if pkg is None:                                    # firmware update fwupd found on LVFS
        update.set_check("sha256", NOT_APPLICABLE, "fwupd downloads the firmware and compares its checksum "
                                                   "with the LVFS metadata")
        update.set_check("manifest", NOT_APPLICABLE, "listed in LVFS metadata, whose signature fwupd verifies")
        update.set_check("blocklist", NOT_APPLICABLE, "device firmware, not a Windows kernel driver")
        update.set_check("publisher", NOT_APPLICABLE, "the firmware's signature is checked by fwupd and the device")
        return
    tool = "the package manager"
    if pkg.get("origin") == "linux-repo":
        update.set_check("manifest", NOT_APPLICABLE, "recommended by the distribution's own driver tool; "
                                                     "not listed in a SafeDriver manifest")
    else:
        update.set_check("manifest", PASSED, "listed in a manifest whose Ed25519 signature matches a pinned key")
    update.set_check("sha256", NOT_APPLICABLE, f"downloaded from the distribution repository; {tool} checks it")
    update.set_check("blocklist", NOT_APPLICABLE, "Linux package, not a Windows kernel driver")
    update.set_check("publisher", NOT_APPLICABLE, f"{tool} verifies the repository signature with the "
                                                  "distribution's keys")


def _unpack_for_inspection(path: Path, fmt: str, dest: Path) -> bool:
    """Unpack a driver package so its .sys and .cat files can be checked. False if it cannot be
    done here (a .cab off Windows): the elevated helper unpacks and checks it in every case."""
    if fmt == "cab" and common.OS_NAME != "windows":
        return False
    try:
        installer.unpack_package(path, fmt, dest)
    except InstallError as exc:
        raise VerificationError(str(exc)) from exc
    return True


def _inspect_driver_package(update: Update, ctx: Context, path: Path) -> None:
    """User-side LOLDrivers check and catalog-signature check of an unpacked driver package.
    The elevated helper repeats both before installing; this run is what makes the result
    visible before the user decides."""
    art = update.package["artifact"]
    sig = art["signature"]
    catalog_signed = sig["type"] == "authenticode" and sig.get("target", "artifact") == "catalog"
    if ctx.demo:
        update.set_check("blocklist", SKIPPED, "demo payload: random bytes, not a driver package")
        return
    tmp = Path(tempfile.mkdtemp(prefix="sd-inspect-"))
    try:
        if not _unpack_for_inspection(path, art["format"], tmp):
            why = "a .cab can only be unpacked on Windows; the installer checks it again before installing"
            update.set_check("blocklist", SKIPPED, why)
            if catalog_signed:
                update.set_check("publisher", SKIPPED, why)
            return
        blocklist = session_blocklist(ctx)
        if blocklist is None:
            update.set_check("blocklist", SKIPPED, f"LOLDrivers database offline ({ctx.blocklist_error or 'unreachable'}); "
                                                   "checked again before installing")
        else:
            try:
                checked = loldrivers.check_directory(tmp, blocklist)
            except loldrivers.SecurityAlert as alert:
                update.set_check("blocklist", FAILED, str(alert))
                raise
            update.set_check("blocklist", PASSED, f"{len(checked)} .sys file(s) compared with {len(blocklist)} "
                                                  "known vulnerable or malicious driver hashes: no match"
                             if checked else "the package contains no .sys files")
        if catalog_signed:
            try:
                cats = verifier.verify_catalogs(tmp, sig["subject"], sig.get("certificate_thumbprint"))
            except VerificationError as exc:
                update.set_check("publisher", FAILED, str(exc))
                raise
            update.set_check("publisher", PASSED, f"Authenticode: {', '.join(cats)} signed by "
                                                  f"{verifier.describe_subjects(sig['subject'])}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)        # unpacked files never stay on disk


def _download_manifest_package(update: Update, ctx: Context, progress=None) -> Path:
    art = update.package["artifact"]
    sig = art["signature"]
    if ctx.demo:
        update.set_check("manifest", SKIPPED, "demo manifest, signed with a throwaway key that is not pinned")
    else:
        update.set_check("manifest", PASSED, "listed in a manifest whose Ed25519 signature matches a pinned key")
    try:
        path = verifier.secure_download(art["url"], art["sha256"], art["size"], ctx.quarantine, art["filename"],
                                        allow_loopback_http=ctx.allow_loopback_http, progress=progress)
    except VerificationError as exc:
        update.set_check("sha256", FAILED, str(exc))
        raise
    update.sha256, update.path = art["sha256"], str(path)
    update.set_check("sha256", PASSED, f"{art['size']} bytes match the SHA-256 in the signed manifest")
    if ctx.demo:
        update.set_check("publisher", SKIPPED, "demo payload has no publisher signature")
        return path
    try:
        if sig["type"] == "authenticode" and sig.get("target", "artifact") == "artifact":
            info = verifier.verify_authenticode(path, sig["subject"], sig.get("certificate_thumbprint"))
            update.set_check("publisher", PASSED, f"Authenticode signature by {info.subject}")
        elif sig["type"] == "gpg":
            sig_file = verifier.fetch_small(sig["signature_url"], ctx.quarantine / (path.name + ".sig"),
                                            allow_loopback_http=ctx.allow_loopback_http)
            verifier.verify_gpg(path, sig_file, sig["fingerprint"])
            update.signature_file = str(sig_file)
            update.set_check("publisher", PASSED, f"GPG signature by pinned key {sig['fingerprint']}")
        elif sig["type"] == "delegated":
            update.set_check("publisher", NOT_APPLICABLE, f"checked by {sig['verifier']} when installing")
    except VerificationError as exc:
        update.set_check("publisher", FAILED, str(exc))
        raise
    return path


class ChannelTrust(Exception):
    """A Windows Update driver that only an administrator can fetch: no file to check yet."""

    def __init__(self, catalog_reason: str, wua_reason: str):
        super().__init__(f"{catalog_reason}; {wua_reason}")
        self.catalog_reason, self.wua_reason = catalog_reason, wua_reason


def _download_catalog_package(update: Update, ctx: Context, progress=None) -> Path:
    """Fetch a catalog / Windows Update driver as the ordinary user and record the SHA-256 check.

    Sources, in order: the public catalog (gives a digest); for Windows Update drivers the URL
    WUA reported; then the Windows Update Agent itself. Only "this source has no copy" moves on
    to the next source; a download that fails its checks never does."""
    pkg, art = update.package, update.package["artifact"]
    wua = pkg.get("origin") == "windows-update"
    where = "offered by Windows Update for this PC" if wua else "found in the Microsoft Update Catalog"
    update.set_check("manifest", NOT_APPLICABLE, f"{where}, not in a signed manifest; "
                                                 "Microsoft's driver signature is required instead")
    try:
        info = ms_catalog.resolve_download(pkg)         # same update IDs; also gives the file's digest
    except ms_catalog.CatalogError as exc:
        common.audit("catalog.download_unavailable", update=pkg["update_id"], reason=str(exc))
        if not wua:
            update.set_check("sha256", FAILED, f"could not get the file: {exc}")
            raise
        if not art.get("url"):
            return _fetch_through_wua(update, ctx, str(exc))
        common.audit("wua.download_fallback", update=pkg["update_id"], reason=str(exc))
        info = ms_catalog.CatalogFile(ms_catalog.normalise_download_url(art["url"]))
    try:
        path, digest, size = verifier.download_from_host(
            info.url, ctx.quarantine, art["filename"], host_ok=ms_catalog.is_download_host,
            max_size=ms_catalog.MAX_DRIVER_BYTES, expected_sha1=info.sha1 or None,
            expected_sha256=info.sha256 or None, allow_loopback_http=ctx.allow_loopback_http, progress=progress)
    except VerificationError as exc:
        update.set_check("sha256", FAILED, str(exc))
        raise
    art.update(url=info.url, sha256=digest, size=size)
    update.sha256, update.path = digest, str(path)
    if info.sha1 or info.sha256:
        update.set_check("sha256", PASSED, f"{size} bytes match the {'SHA-256' if info.sha256 else 'SHA-1'} "
                                           "digest Microsoft publishes for this file")
    else:
        update.set_check("sha256", SKIPPED, "Microsoft published no digest for this file; it was hashed locally "
                                            "only, so later steps can detect changes")
    return path


def wua_package(update_id: str, work: Path) -> tuple[Path, str]:
    """Windows Update Agent download -> driver package folder (work/package). Returns the folder
    and a SHA-256 over its files (names and contents) for the record. Raises
    WindowsUpdateError from the agent, InstallError when the files hold no INF driver."""
    from .discovery import windows_update
    files = windows_update.fetch_payload(update_id, work / "payload", ms_catalog.MAX_DRIVER_BYTES)
    folder = installer.build_package_dir(files, (work / "payload").resolve(), work / "package")
    return folder, verifier.tree_sha256(folder)


def _fetch_through_wua(update: Update, ctx: Context, catalog_reason: str) -> Path:
    """The public catalog has no copy (typical for OEM drivers): ask the Windows Update Agent.
    The folder it yields is checked here (LOLDrivers, catalog signer) so the badge is final; the
    elevated installer asks the agent again and repeats every check on its own copy.
    Raises ChannelTrust when only an administrator may download it."""
    from .discovery import windows_update
    pkg, art = update.package, update.package["artifact"]
    verifier.private_dir(ctx.quarantine)
    work = Path(tempfile.mkdtemp(prefix=f"wua-{pkg['update_id'][:8]}-", dir=ctx.quarantine))
    try:
        folder, digest = wua_package(pkg["update_id"], work)
    except windows_update.WindowsUpdateError as exc:
        shutil.rmtree(work, ignore_errors=True)
        if exc.needs_admin:
            raise ChannelTrust(catalog_reason, str(exc)) from None
        update.set_check("sha256", FAILED, f"could not get the file: {catalog_reason}; {exc}")
        raise VerificationError(f"{catalog_reason}; {exc}") from None
    except InstallError as exc:
        shutil.rmtree(work, ignore_errors=True)
        update.set_check("sha256", FAILED, str(exc))
        raise VerificationError(str(exc)) from None
    art.update(format="dir", acquire="windows-update-agent", acquired="windows-update-agent", sha256="", size=0)
    update.sha256, update.path = "", str(folder)
    update.set_check("sha256", PASSED, f"downloaded by the Windows Update Agent, which checks every file against "
                                       f"Microsoft-signed update metadata (the public catalog has no copy: "
                                       f"{catalog_reason}); files SHA-256 {digest[:16]}…; the installer fetches "
                                       f"it again as administrator and repeats every check")
    return folder


def _trust_windows_update_channel(update: Update, why: ChannelTrust) -> None:
    """Partial, not None: Windows offers this driver to this PC but lets only an administrator
    download it. Nothing could be inspected yet, so the installer (elevated) has the Windows
    Update Agent fetch it and runs every check on the .cab before anything is installed."""
    art = update.package["artifact"]
    art.update(acquire="windows-update-agent", sha256="", size=0)
    later = "the installer, running as administrator, checks this on the downloaded package before installing"
    update.set_check("sha256", SKIPPED, f"not downloaded yet: {why.catalog_reason}, and {why.wua_reason}. The "
                                        "installer has the Windows Update Agent download it (verified against "
                                        "Microsoft-signed update metadata) and hashes it")
    update.set_check("blocklist", SKIPPED, f"no driver files to inspect before installing; {later}")
    update.set_check("publisher", SKIPPED, f"Microsoft's driver catalog signature cannot be read before the "
                                           f"download; {later}")
    update.sha256, update.path = "", ""
    update.status, update.detail = "verified", "Windows Update channel: " + _summary(update)
    common.audit("verify.channel_trust", update=update.name, catalog=why.catalog_reason, wua=why.wua_reason)


def _summary(update: Update) -> str:
    words = {PASSED: "OK", SKIPPED: "skipped", FAILED: "FAILED"}
    return "; ".join(f"{CHECK_SHORT[c.key]} {words[c.state]}" for c in update.checks if c.state in words)


def verify_update(update: Update, ctx: Context, progress=None) -> None:
    """Download and verify one update as the ordinary user, recording every check on
    update.checks. Sets update.status ("verified" / "failed"; "delegated" is left alone)."""
    pkg = update.package
    art = (pkg or {}).get("artifact")
    if not art:
        _record_delegated(update)
        return
    for key in CHECK_ORDER:
        update.set_check(key, SKIPPED, _NOT_YET)
    try:
        if pkg.get("origin") in CATALOG_ORIGINS:
            path = _download_catalog_package(update, ctx, progress)
        else:
            path = _download_manifest_package(update, ctx, progress)
        if pkg["install"]["method"] == "pnputil":
            _inspect_driver_package(update, ctx, path)
        else:
            update.set_check("blocklist", NOT_APPLICABLE, "not a Windows kernel driver package")
        update.status, update.detail = "verified", _summary(update)
    except ChannelTrust as why:
        _trust_windows_update_channel(update, why)
    except (VerificationError, ms_catalog.CatalogError) as exc:
        _purge(ctx, update.sha256 or art.get("sha256", ""))   # also when a later check fails after the hash passed
        _record_failure(update, exc)
        update.status, update.detail = "failed", f"{exc} - file purged"
    finally:
        if art.get("acquire") == "windows-update-agent" and update.path:
            # The agent's folder was only for these checks: the installer fetches its own copy.
            work = Path(update.path).parent
            if ctx.quarantine.resolve() in work.resolve().parents:
                shutil.rmtree(work, ignore_errors=True)
            update.path = ""
    if update.status == "failed":
        update.path = ""


def _record_failure(update: Update, exc: Exception) -> None:
    """Make the reason visible on the checks themselves: the step that was running is FAILED
    with the actual error (unless it already recorded one), and every later step names it."""
    failed = next((c for c in update.checks if c.state == FAILED), None)
    if failed is None:
        failed = next((c for c in update.checks if c.reason == _NOT_YET), None)
        if failed is not None:
            update.set_check(failed.key, FAILED, str(exc))
    for c in update.checks:
        if c.reason == _NOT_YET:
            update.set_check(c.key, SKIPPED, f"not reached: {failed.label if failed else 'an earlier step'} "
                                             f"failed ({failed.reason if failed else exc})")
    common.audit("verify.failed", update=update.name, source=update.source,
                 step=failed.label if failed else "", reason=str(exc))


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
    return elevation.helper_command(plan_path)


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
        results = common.system_state_dir() / "results"
        try:
            result = json.loads((results / f"{plan_id}.json").read_text())
        except (OSError, ValueError):
            result = {"status": "failed", "items": [],
                      "detail": f"the elevated helper exited with code {rc} and left no result"}
        if not result.get("log"):                          # crashed before writing it: use the live log
            result["log"] = read_helper_log(results / f"{plan_id}.log")
        forward_helper_log(result.get("log") or [])
        if result.get("status") != "ok" and rc not in (0, None):
            result.setdefault("helper_rc", rc)
    if result.get("status") == "security_alert":            # purge the offending download on our side too
        for u in todo:
            if update_key(u) in (result.get("alerts") or []):
                _purge(ctx, u.sha256)
                u.set_check("blocklist", FAILED, result.get("detail", "blocked"))
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
    origin = "windows-update" if desc.get("origin") == "windows-update" else "ms-catalog"
    prefix = "windowsupdate" if origin == "windows-update" else "mscatalog"
    subjects = trust.WINDOWS_UPDATE_SUBJECTS if origin == "windows-update" else trust.MS_WHQL_SUBJECT
    artifact = {"filename": f"{update_id}.cab", "format": "cab",
                "signature": {"type": "authenticode", "target": "catalog", "subject": subjects}}
    if origin == "windows-update" and art.get("acquire") == "windows-update-agent":
        # The helper asks the Windows Update Agent itself (Microsoft-signed metadata) for the
        # files, builds the driver folder from whatever it hands over, then runs every check.
        artifact.update(acquire="windows-update-agent", format="dir")
    else:
        sha256, size = str(art.get("sha256", "")), art.get("size")
        if not manifest.SHA256_RE.match(sha256) or not isinstance(size, int) or not 0 < size <= ms_catalog.MAX_DRIVER_BYTES:
            raise VerificationError("discovered package was not downloaded and hashed")
        artifact.update(sha256=sha256, size=size)
    return {"id": f"{prefix}.{update_id}", "origin": origin, "update_id": update_id,
            "name": str(desc.get("name") or update_id)[:200], "version": str(desc.get("version") or "0")[:64],
            "artifact": artifact, "install": {"method": "pnputil", "reboot_required": False}}


def _acquire_through_wua(pkg: dict, staging: Path) -> Path:
    """Helper side of a Windows Update item: as administrator, have the agent hand over the
    update and build the driver folder that installer.prepare then checks (LOLDrivers, catalog
    signer) and installs."""
    from .discovery import windows_update
    try:
        folder, digest = wua_package(pkg["update_id"], staging / ("wua-" + pkg["update_id"]))
    except windows_update.WindowsUpdateError as exc:
        raise VerificationError(f"Windows Update download as administrator failed: {exc}") from None
    pkg["artifact"]["sha256"] = digest
    common.audit("helper.wua_acquired", update=pkg["update_id"], name=pkg["name"], files_sha256=digest,
                 files=sum(1 for f in folder.rglob("*") if f.is_file()),
                 infs=[f.name for f in folder.rglob("*.inf")][:10])
    return folder


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
        if origin in CATALOG_ORIGINS:
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


def _reason(exc: BaseException) -> str:
    """Never an empty reason: KeyError('x') and friends say what they are."""
    text = str(exc).strip()
    return text if text and text not in ("''", '""') else f"{type(exc).__name__}: {exc!r}"


def _refuse(result: dict, ident: str, reason: str, name: str = "", step: str = "") -> None:
    reason = reason.strip() or "refused without a reason (bug): see the log"
    if step:
        reason = f"{step}: {reason}"
    common.audit("helper.refused", item=ident, name=name or ident, reason=reason)
    result["items"].append({"id": ident, "name": name or ident, "status": "refused", "rc": -1, "detail": reason,
                            "commands": []})


# ------------------------------------------------------- helper log to the GUI
HELPER_LOG_MAX = 400


def read_helper_log(path: Path) -> list[dict]:
    """The helper's live log (JSON lines), or [] if it never started writing one."""
    out = []
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                if isinstance(rec, dict) and isinstance(rec.get("event"), str):
                    out.append(rec)
    except OSError:
        return []
    return out[-HELPER_LOG_MAX:]


def forward_helper_log(records: list[dict]) -> None:
    """Replay the elevated helper's events into this process's audit log as "elevated.<event>",
    so the LOG drawer and --debug show what happened as administrator, in order."""
    for rec in records[-HELPER_LOG_MAX:]:
        data = rec.get("data") if isinstance(rec.get("data"), dict) else {}
        common.audit("elevated." + str(rec["event"])[:60], helper_ts=str(rec.get("ts", ""))[:32],
                     **{str(k)[:40]: v for k, v in list(data.items())[:20]})


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
            _refuse(result, ident, _reason(exc), step="plan check")

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
                if art and art.get("acquire") == "windows-update-agent":
                    staged = _acquire_through_wua(pkg, staging)
                elif art:
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
                _refuse(result, ident, str(alert), name, step="LOLDrivers BYOVD check")
                result.update(status="security_alert", detail=str(alert), alerts=[ident], matches=alert.matches)
                return
            except (VerificationError, InstallError, OSError, KeyError, TypeError) as exc:
                _refuse(result, ident, _reason(exc), name, step="verification before installing")
        if not prepared:
            reasons = "; ".join(f"{i['name']}: {i['detail']}" for i in result["items"][:3])
            result.update(status="refused", detail=f"no item passed verification, nothing was installed ({reasons})")
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
    records: list[dict] = []
    live = {"fh": None}

    def keep(rec: dict) -> None:
        # Every event of this run, for the front end's LOG drawer: in the result, and line by
        # line in results/<plan>.log so even a crash leaves a trail. Readable, never secret.
        small = {"ts": rec["ts"], "event": rec["event"], "data": rec["data"]}
        records.append(small)
        if live["fh"]:
            try:
                live["fh"].write(json.dumps(small, default=str)[:4000] + "\n")
                live["fh"].flush()
            except (OSError, ValueError):
                pass

    common.audit_log().listeners.append(keep)
    out = common.system_state_dir() / "results"
    try:
        plan = json.loads(_read_capped(plan_path, 1 << 20))
        plan_id = str(plan.get("plan_id", "")) if isinstance(plan, dict) else ""
        if not re.fullmatch(r"[0-9a-f]{32}", plan_id):
            raise VerificationError("plan id is malformed")
        result["plan_id"] = plan_id
        out.mkdir(parents=True, exist_ok=True)
        live["fh"] = open(out / f"{plan_id}.log", "w", encoding="utf-8")
        if os.name != "nt":
            os.chmod(out, 0o755)
            os.chmod(out / f"{plan_id}.log", 0o644)
        common.audit("helper.start", plan=plan_id, items=len(plan.get("items") or []))
        _run_plan(plan, result, trusted_keys)
    except (VerificationError, InstallError, OSError, ValueError, KeyError) as exc:
        result.update(status="refused", detail=_reason(exc))
    except Exception as exc:                   # a bug must still leave a result with its reason
        result.update(status="failed", detail=f"the helper stopped with an internal error: {_reason(exc)}")
        common.audit("helper.crashed", error=_reason(exc))
    finally:
        common.audit("helper.done", plan=result["plan_id"], status=result["status"], detail=result["detail"],
                     items=[f"{i['name']}: {i['status']}: {i['detail']}"[:300] for i in result["items"]][:20])
        common.audit_log().listeners.remove(keep)
        if live["fh"]:
            live["fh"].close()
    result["log"] = [{**r, "data": json.loads(json.dumps(r["data"], default=str))} for r in records[-HELPER_LOG_MAX:]]
    if result["plan_id"]:
        target = out / f"{result['plan_id']}.json"
        target.write_text(json.dumps(result, indent=1))
        if os.name != "nt":
            os.chmod(target, 0o644)
    return result
