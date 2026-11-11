"""Signed manifest: authenticity, freshness, structural checks, device matching."""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import re
import sys
from pathlib import Path

from . import common, trust
from .common import VerificationError
from .model import Device, Update, compare_versions, is_newer

SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,127}$")
_FILE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$")
_PKG_RE = re.compile(r"^[a-z0-9][a-z0-9+._-]{0,127}$")
_INF_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_./\\ -]*\.inf$", re.I)
_GUID_RE = re.compile(r"^\{[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}\}$")
METHODS = ("pnputil", "fwupd", "package-manager")
MAX_MANIFEST_BYTES = 8 << 20


def _require(cond: bool, what: str) -> None:
    if not cond:
        raise VerificationError(f"manifest is malformed: {what}")


def _url_ok(url: object, loopback_ok: bool) -> bool:
    url = str(url)
    return url.startswith("https://") or (loopback_ok and url.startswith("http://127.0.0.1:"))


def validate_package(pkg: dict, loopback_ok: bool = False) -> None:
    """Checks the elevated helper relies on. Mirrors schema/manifest.schema.json."""
    pid = pkg.get("id", "")
    _require(isinstance(pid, str) and bool(_ID_RE.match(pid)), f"package id {pid!r}")
    inst = pkg.get("install") or {}
    _require(inst.get("method") in METHODS, f"{pid}: install.method")
    plat = pkg.get("platform") or {}
    _require(plat.get("os") in ("windows", "linux") and isinstance(plat.get("arch"), list), f"{pid}: platform")
    _require(isinstance(pkg.get("hardware_ids"), list) and pkg["hardware_ids"], f"{pid}: hardware_ids")
    _require(isinstance(pkg.get("version"), str) and bool(pkg["version"]), f"{pid}: version")
    if "class_guid" in pkg:
        _require(bool(_GUID_RE.match(pkg["class_guid"])), f"{pid}: class_guid")
    if "package_name" in inst:
        _require(bool(_PKG_RE.match(str(inst["package_name"]))), f"{pid}: install.package_name")
    if "inf_path" in inst:
        _require(bool(_INF_RE.match(inst["inf_path"])) and ".." not in inst["inf_path"], f"{pid}: install.inf_path")
    art = pkg.get("artifact")
    if art is None:
        _require(inst["method"] == "package-manager" and "package_name" in inst,
                 f"{pid}: artifact may only be omitted for a repository package")
        return
    _require(bool(SHA256_RE.match(str(art.get("sha256", "")))), f"{pid}: artifact.sha256")
    _require(isinstance(art.get("size"), int) and art["size"] > 0, f"{pid}: artifact.size")
    _require(_url_ok(art.get("url", ""), loopback_ok), f"{pid}: artifact.url must be https")
    _require(bool(_FILE_RE.match(str(art.get("filename", "")))), f"{pid}: artifact.filename")
    sig = art.get("signature") or {}
    _require(sig.get("type") in ("authenticode", "gpg", "delegated"), f"{pid}: artifact.signature.type")
    if sig["type"] == "authenticode":
        _require(bool(sig.get("subject")) and sig.get("target", "artifact") in ("artifact", "catalog"),
                 f"{pid}: authenticode signature")
    if sig["type"] == "gpg":
        _require(_url_ok(sig.get("signature_url", ""), loopback_ok)
                 and bool(re.match(r"^[A-F0-9]{40,64}$", str(sig.get("fingerprint", "")))), f"{pid}: gpg signature")


def load_manifest(raw: bytes, signature_b64: bytes, *, trusted_keys: dict[str, str] | None = None,
                  check_rollback: bool = True, seq_dir: Path | None = None,
                  now: dt.datetime | None = None, loopback_ok: bool = False) -> dict:
    """Return the parsed manifest only if signature, expiry, sequence and structure all pass.

    `trusted_keys` defaults to the keys pinned in trust.py. It exists as a
    parameter for tests and the in-process demo; no front end exposes it.
    """
    keys = trust.PINNED_MANIFEST_KEYS if trusted_keys is None else trusted_keys
    if not keys:
        raise VerificationError("no manifest signing key is pinned in core/trust.py "
                                "(run tools/keygen.py --pin); refusing all manifests")
    if len(raw) > MAX_MANIFEST_BYTES:
        raise VerificationError("manifest is too large")
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:
        raise VerificationError("the 'cryptography' package is required to verify manifests") from exc
    try:
        sig = base64.b64decode(signature_b64.strip(), validate=True)
    except ValueError as exc:
        raise VerificationError("manifest signature file is not valid base64") from exc
    signer = None
    for kid, pub in keys.items():
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub)).verify(sig, raw)
            signer = kid
            break
        except (InvalidSignature, ValueError):
            continue
    if signer is None:
        common.audit("manifest.rejected", reason="no pinned key verifies the signature")
        raise VerificationError("manifest signature is invalid or not made by a pinned key")
    try:
        manifest = json.loads(raw)
        _require(str(manifest["schema_version"]).startswith("1."), "unsupported schema_version")
        expires = dt.datetime.fromisoformat(manifest["expires"].replace("Z", "+00:00"))
        _require(isinstance(manifest["sequence"], int) and isinstance(manifest["packages"], list), "sequence/packages")
    except (ValueError, KeyError, TypeError) as exc:
        raise VerificationError(f"manifest is malformed: {exc}") from exc
    if expires <= (now or dt.datetime.now(dt.timezone.utc)):
        common.audit("manifest.rejected", reason="expired", expires=manifest["expires"])
        raise VerificationError(f"manifest expired on {manifest['expires']}")
    for pkg in manifest["packages"]:
        validate_package(pkg, loopback_ok)  # loopback_ok: demo and tests only
    if check_rollback:
        seq_file = (seq_dir or common.state_dir()) / "manifest.sequence"
        try:
            last = int(seq_file.read_text().strip())
        except (OSError, ValueError):
            last = 0
        if manifest["sequence"] < last:
            common.audit("manifest.rejected", reason="rollback", sequence=manifest["sequence"], last=last)
            raise VerificationError(f"manifest sequence {manifest['sequence']} is older than {last} (rollback)")
        seq_file.parent.mkdir(parents=True, exist_ok=True)
        seq_file.write_text(str(manifest["sequence"]))
    common.audit("manifest.accepted", sequence=manifest["sequence"], signer=signer,
                 packages=len(manifest["packages"]), sha256=hashlib.sha256(raw).hexdigest())
    return manifest


def package_by_id(manifest: dict, package_id: str) -> dict | None:
    return next((p for p in manifest.get("packages", []) if p.get("id") == package_id), None)


def _distro_ids() -> set[str]:
    ids: set[str] = set()
    try:
        for line in Path("/etc/os-release").read_text().splitlines():
            key, _, val = line.partition("=")
            if key in ("ID", "ID_LIKE"):
                ids.update(val.strip().strip('"').lower().split())
    except OSError:
        pass
    return ids


def applies_to_platform(pkg: dict, os_name: str | None = None, arch: str | None = None,
                        distros: set[str] | None = None, os_build: int | None = None) -> bool:
    plat = pkg["platform"]
    os_name = os_name or common.OS_NAME
    if plat["os"] != os_name or (arch or common.ARCH) not in plat["arch"]:
        return False
    if os_name == "linux" and plat.get("distros"):
        if not set(plat["distros"]) & (distros if distros is not None else _distro_ids()):
            return False
    if os_name == "windows" and plat.get("min_os_build"):
        build = os_build if os_build is not None else getattr(
            getattr(sys, "getwindowsversion", lambda: None)(), "build", None)
        if build is not None and build < plat["min_os_build"]:
            return False
    return True


def find_updates(devices: list[Device], manifest: dict | None, fwupd_upgrades: dict[str, dict] | None = None,
                 *, os_name: str | None = None, arch: str | None = None) -> list[Update]:
    updates: list[Update] = []
    for dev in devices:
        rel = (fwupd_upgrades or {}).get(dev.address) if dev.kind == "fwupd" else None
        if rel:
            digest = next((c for c in rel.get("Checksum", []) if len(c) == 64), "")
            updates.append(Update(dev, rel.get("Name", dev.name), dev.driver_version, rel.get("Version", "?"),
                                  "fwupd / LVFS", digest, None, "delegated",
                                  "fwupd verifies this against LVFS-signed metadata"))
    for pkg in (manifest or {}).get("packages", []):
        if not applies_to_platform(pkg, os_name, arch):
            continue
        wanted = set(pkg["hardware_ids"])
        for dev in devices:
            if wanted.isdisjoint(dev.hardware_ids):
                continue
            if pkg.get("class_guid") and dev.class_guid and pkg["class_guid"] != dev.class_guid:
                continue  # same hardware ID, different device class (e.g. audio function of a GPU)
            installed = "" if "in-kernel" in dev.driver_version else dev.driver_version
            if not is_newer(pkg["version"], installed):
                continue
            floor = pkg.get("min_installed_version")
            if floor and installed and compare_versions(installed, floor) < 0:
                continue  # stepping-stone update required first
            art = pkg.get("artifact") or {}
            updates.append(Update(dev, pkg["name"], dev.driver_version or "unknown", pkg["version"],
                                  pkg["upstream"]["source"], art.get("sha256", ""), pkg,
                                  "pending" if art else "delegated",
                                  "" if art else "installed from the distro repository; verified by the package manager"))
    common.audit("plan", updates=[{"device": u.device.name, "to": u.available, "source": u.source} for u in updates])
    return updates
