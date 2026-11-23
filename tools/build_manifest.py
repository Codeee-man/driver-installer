#!/usr/bin/env python3
"""Build and sign a SafeDriver manifest from a directory of driver files.

    python tools/build_manifest.py --driver-dir drivers/ --url-prefix https://dl.example.org/drivers \\
        --private-key signing.pem --output manifest.json

What it does
  1. Scans --driver-dir (recursively) for .inf, .sys, .tar.gz and .fw files and records the
     size and SHA-256 of each one in <output>.files.json.
  2. Turns every .inf into one manifest package. The INF supplies the version (DriverVer),
     class GUID, provider, architecture and hardware IDs. The INF's folder (its .sys, .cat
     and the rest) is packed into a reproducible zip in --dist-dir; that zip is the artifact
     whose size and SHA-256 go into the manifest. Upload the zips to --url-prefix.
  3. Writes the manifest (schema 1.1), validates it with the same checks the client runs, and
     signs the exact bytes: <output>.sig holds the base64 Ed25519 signature.

Limits (by design of schema/manifest.schema.json and the client, not of this tool)
  * Signing is Ed25519 only. Clients verify nothing else, so an RSA key is refused rather
    than producing a manifest nobody can verify. Accepted key files: an Ed25519 PEM (PKCS#8),
    or the hex file written by tools/keygen.py.
  * .sys files are covered through the zip of the .inf they belong to. A .sys with no .inf
    beside it, and every .tar.gz and .fw, is hashed and listed in <output>.files.json but
    NOT put in the manifest: the schema has no artifact format for them and the client has
    no way to install them (fwupd needs a .cab, package managers need .deb/.rpm/.pkg).

  * One package is emitted per INF with the union of its architectures and hardware IDs; an
    ID that the INF lists for one architecture only is offered on the others too, where
    pnputil then reports "no device needed it".

Exit codes: 0 manifest written and signed, 1 nothing to publish or validation failed, 2 bad input.
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import getpass
import hashlib
import json
import os
import re
import sys
import time
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from core import manifest as manifest_mod, trust  # noqa: E402
from core.common import VerificationError  # noqa: E402

SCAN_SUFFIXES = (".inf", ".sys", ".tar.gz", ".fw")
SCHEMA_PATH = ROOT / "schema" / "manifest.schema.json"
ARCH = {"ntamd64": "x86_64", "ntarm64": "aarch64", "ntx86": "x86"}
OID_CODE_SIGNING, OID_TIME_STAMPING = "1.3.6.1.5.5.7.3.3", "1.3.6.1.5.5.7.3.8"
_PCI = re.compile(r"PCI\\VEN_([0-9A-F]{4})&DEV_([0-9A-F]{4})(?:&SUBSYS_([0-9A-F]{4})([0-9A-F]{4}))?", re.I)
_USB = re.compile(r"USB\\VID_([0-9A-F]{4})&PID_([0-9A-F]{4})", re.I)
_VERSION = re.compile(r"^[0-9]+(\.[0-9]+)*$")
_GUID = re.compile(r"^\{[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}\}$")


class BuildError(Exception):
    pass


# ------------------------------------------------------------------ files
def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


def scan(driver_dir: Path, skip: Path) -> list[Path]:
    found = []
    for path in sorted(driver_dir.rglob("*")):
        if path.is_file() and not path.is_symlink() and path.name.lower().endswith(SCAN_SUFFIXES) \
                and skip not in path.resolve().parents:
            found.append(path)
    return found


def slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


# -------------------------------------------------------------------- INF
def read_inf(path: Path) -> dict[str, list[str]]:
    raw = path.read_bytes()
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        text = raw.decode("utf-16")
    else:
        try:
            text = raw.decode("utf-8-sig")
        except UnicodeDecodeError:
            text = raw.decode("cp1252", "replace")
    sections: dict[str, list[str]] = {}
    current = None
    for line in text.splitlines():
        out, quoted = "", False
        for ch in line:                      # drop ; comments outside quotes
            if ch == '"':
                quoted = not quoted
            elif ch == ";" and not quoted:
                break
            out += ch
        line = out.strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1].strip().lower()
            sections.setdefault(current, [])
        elif current is not None:
            sections[current].append(line)
    return sections


def pairs(lines: list[str]) -> list[tuple[str, str]]:
    return [(k.strip(), v.strip()) for k, _, v in (ln.partition("=") for ln in lines) if _]


def manifest_id(raw: str) -> str:
    """INF hardware ID -> manifest form. A SUBSYS-qualified ID stays subsystem-specific."""
    m = _PCI.search(raw)
    if m:
        ven, dev, sdev, sven = (g.lower() if g else g for g in m.groups())
        return f"pci:{ven}:{dev}:{sven}:{sdev}" if sven else f"pci:{ven}:{dev}"
    m = _USB.search(raw)
    if m:
        return f"usb:{m.group(1).lower()}:{m.group(2).lower()}"
    return "raw:" + raw.lower()


def parse_inf(path: Path) -> dict:
    sec = read_inf(path)
    strings = {k.lower(): v.strip('"') for k, v in pairs(sec.get("strings", []))}

    def resolve(token: str) -> str:
        token = token.strip().strip('"')
        m = re.fullmatch(r"%(.+)%", token)
        return strings.get(m.group(1).lower(), m.group(1)) if m else token

    version = {k.lower(): v for k, v in pairs(sec.get("version", []))}
    driver_ver = [p.strip() for p in version.get("driverver", "").split(",")]
    if len(driver_ver) != 2 or not _VERSION.match(driver_ver[1]):
        raise BuildError("no usable DriverVer=<mm/dd/yyyy>,<version> in [Version]")
    try:
        release = dt.datetime.strptime(driver_ver[0], "%m/%d/%Y").date().isoformat()
    except ValueError:
        release = None

    ids, archs, description = [], set(), ""
    for _, rhs in pairs(sec.get("manufacturer", [])):
        base, *decorations = [p.strip() for p in rhs.split(",")]
        archs.update(a for d in decorations for key, a in ARCH.items() if d.lower().startswith(key))
        for name in [base] + [f"{base}.{d}" for d in decorations]:
            for lhs, model in pairs(sec.get(name.lower(), [])):
                description = description or resolve(lhs)
                for raw in [p.strip().strip('"') for p in model.split(",")[1:] if p.strip()]:
                    hid = manifest_id(raw)
                    if hid not in ids:
                        ids.append(hid)
    if not ids:
        raise BuildError("no hardware IDs found in the INF's model sections")
    guid = version.get("classguid", "").strip().lower()
    return {"version": driver_ver[1], "release_date": release, "hardware_ids": ids,
            "arch": sorted(archs) or ["x86_64"], "class_guid": guid if _GUID.match(guid) else None,
            "vendor": resolve(version.get("provider", "")) or "Unknown",
            "name": description or path.stem}


# ------------------------------------------------------- catalog publisher
def catalog_signer(cat: Path) -> tuple[str, str] | None:
    """(subject pin, SHA-1 thumbprint) of the code-signing certificate inside a .cat, if unambiguous."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.serialization import pkcs7
    from cryptography.x509.oid import NameOID
    try:
        certs = pkcs7.load_der_pkcs7_certificates(cat.read_bytes())
    except Exception:
        return None
    issuers = {c.issuer.rfc4514_string() for c in certs if c.issuer != c.subject}
    leaves = []
    for cert in certs:
        if cert.subject.rfc4514_string() in issuers:
            continue
        try:
            usages = {u.dotted_string for u in cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value}
        except x509.ExtensionNotFound:
            usages = set()
        if OID_TIME_STAMPING in usages and OID_CODE_SIGNING not in usages:
            continue                                    # timestamp countersigner, not the publisher
        leaves.append(cert)
    if len(leaves) != 1:
        return None
    parts = []
    for label, oid in (("O", NameOID.ORGANIZATION_NAME), ("CN", NameOID.COMMON_NAME)):
        values = leaves[0].subject.get_attributes_for_oid(oid)
        if values and '"' not in str(values[0].value):
            value = str(values[0].value)
            parts.append(f'{label}="{value}"' if "," in value else f"{label}={value}")
    if not parts:
        return None
    return ", ".join(parts), leaves[0].fingerprint(hashes.SHA1()).hex().upper()


# -------------------------------------------------------------------- zip
def build_zip(folder: Path, target: Path, skip: Path) -> None:
    """Reproducible archive: sorted names, fixed timestamps and modes, so the same input
    always gives the same SHA-256."""
    target.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for path in sorted(p for p in folder.rglob("*") if p.is_file() and not p.is_symlink()):
            if skip in path.resolve().parents:
                continue
            info = zipfile.ZipInfo(path.relative_to(folder).as_posix(), date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            zf.writestr(info, path.read_bytes(), compresslevel=9)


# ------------------------------------------------------------------- keys
def load_signing_key(path: Path):
    """Ed25519 private key from PEM (PKCS#8 / OpenSSH) or from the hex file tools/keygen.py writes."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
    data = path.read_bytes()
    if b"-----BEGIN" in data:
        loader = serialization.load_ssh_private_key if b"OPENSSH PRIVATE KEY" in data \
            else serialization.load_pem_private_key
        try:
            key = loader(data, password=None)
        except TypeError:                                  # encrypted key
            secret = os.environ.get("SAFEDRIVER_KEY_PASSPHRASE") or getpass.getpass(f"Passphrase for {path}: ")
            key = loader(data, password=secret.encode())
        except ValueError as exc:
            raise BuildError(f"cannot read {path}: {exc}") from exc
    else:
        try:
            key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(data.decode("ascii").strip()))
        except (ValueError, UnicodeDecodeError) as exc:
            raise BuildError(f"{path} is neither a PEM key nor a tools/keygen.py hex key") from exc
    if isinstance(key, rsa.RSAPrivateKey):
        raise BuildError("RSA keys cannot sign SafeDriver manifests: clients verify Ed25519 only "
                         "(schema signing.algorithm). Create a key with tools/keygen.py or "
                         "`openssl genpkey -algorithm ed25519 -out signing.pem`.")
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise BuildError(f"unsupported key type {type(key).__name__}; an Ed25519 key is required")
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    return key, public


# ------------------------------------------------------------------ build
def build_packages(args, files: list[Path], dist: Path, inventory: dict[str, dict]) -> list[dict]:
    packages, used_ids = [], set()
    for inf in [f for f in files if f.suffix.lower() == ".inf"]:
        rel = inf.relative_to(args.driver_dir).as_posix()
        try:
            meta = parse_inf(inf)
            cats = sorted(inf.parent.rglob("*.cat"))
            if not cats:
                raise BuildError("no .cat catalog next to the INF; clients refuse unsigned driver packages")
            if args.publisher:
                signature = {"type": "authenticode", "target": "catalog", "subject": args.publisher}
            else:
                signer = catalog_signer(cats[0])
                if not signer:
                    raise BuildError(f"cannot determine the signer of {cats[0].name}; pass --publisher 'O=...'")
                signature = {"type": "authenticode", "target": "catalog", "subject": signer[0],
                             "certificate_thumbprint": signer[1]}
            pid = f"{slug(meta['vendor']) or 'vendor'}.{slug(inf.stem)}.windows"
            if pid in used_ids:
                pid = f"{pid}.{hashlib.sha256(rel.encode()).hexdigest()[:8]}"
            used_ids.add(pid)
            archive = dist / f"{slug(inf.stem)}-{meta['version']}.zip"
            build_zip(inf.parent, archive, dist)
            package = {
                "id": pid, "name": meta["name"], "vendor": meta["vendor"], "category": "driver",
                "version": meta["version"],
                "platform": {"os": "windows", "arch": meta["arch"]},
                "hardware_ids": meta["hardware_ids"],
                "artifact": {"url": f"{args.url_prefix.rstrip('/')}/{archive.name}", "filename": archive.name,
                             "size": archive.stat().st_size, "sha256": sha256_file(archive), "format": "zip",
                             "signature": signature},
                "install": {"method": "pnputil", "inf_path": inf.name, "reboot_required": args.reboot_required},
                "upstream": {"source": "vendor", "reference_url": args.reference_url or args.url_prefix},
            }
            if meta["release_date"]:
                package["release_date"] = meta["release_date"]
            if meta["class_guid"]:
                package["class_guid"] = meta["class_guid"]
            manifest_mod.validate_package(package)
            packages.append(package)
            for member in inf.parent.rglob("*"):
                key = member.relative_to(args.driver_dir).as_posix()
                if key in inventory:
                    inventory[key].update(in_manifest=True, package=pid, artifact=archive.name)
        except (BuildError, VerificationError, OSError) as exc:
            inventory[rel]["note"] = f"skipped: {exc}"
            print(f"  ! {rel}: {exc}", file=sys.stderr)
    return packages


def validate_against_schema(document: dict) -> None:
    try:
        import jsonschema
    except ImportError:
        print("  note: 'jsonschema' is not installed; ran the client's built-in checks only", file=sys.stderr)
        return
    schema = json.loads(SCHEMA_PATH.read_text())
    errors = sorted(jsonschema.Draft202012Validator(schema).iter_errors(document), key=lambda e: list(e.path))
    if errors:
        raise BuildError("manifest does not match schema: " + "; ".join(
            f"{'/'.join(map(str, e.path)) or '(root)'}: {e.message}" for e in errors[:5]))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Generate a signed SafeDriver manifest from a directory of drivers.")
    ap.add_argument("--driver-dir", type=Path, required=True, help="directory to scan (recursively)")
    ap.add_argument("--url-prefix", required=True, help="https URL the artifacts will be downloadable from")
    ap.add_argument("--private-key", type=Path, required=True, help="Ed25519 key: PEM, or tools/keygen.py hex file")
    ap.add_argument("--output", type=Path, required=True, help="manifest.json to write (plus .sig and .files.json)")
    ap.add_argument("--dist-dir", type=Path, help="where the artifact zips are written (default: <output dir>/dist)")
    ap.add_argument("--publisher", help="Authenticode subject to pin, e.g. 'O=Intel Corporation' "
                                        "(default: read from each package's .cat)")
    ap.add_argument("--publisher-name", default="driver-installer manifest", help="manifest publisher.name")
    ap.add_argument("--reference-url", help="upstream.reference_url (default: --url-prefix)")
    ap.add_argument("--expires-days", type=int, default=14, help="manifest lifetime (default: 14)")
    ap.add_argument("--sequence", type=int, help="manifest sequence number (default: current Unix time)")
    ap.add_argument("--reboot-required", action="store_true", help="mark every package as needing a restart")
    args = ap.parse_args(argv)

    try:
        if not args.driver_dir.is_dir():
            raise BuildError(f"{args.driver_dir} is not a directory")
        if not args.url_prefix.startswith("https://"):
            raise BuildError("--url-prefix must start with https:// (clients refuse anything else)")
        if args.expires_days < 1:
            raise BuildError("--expires-days must be at least 1")
        key, public = load_signing_key(args.private_key)
    except (BuildError, OSError) as exc:
        print(f"build_manifest: {exc}", file=sys.stderr)
        return 2

    args.driver_dir = args.driver_dir.resolve()
    dist = (args.dist_dir or args.output.parent / "dist").resolve()
    files = scan(args.driver_dir, dist)
    inventory = {f.relative_to(args.driver_dir).as_posix(): {
        "size": f.stat().st_size, "sha256": sha256_file(f), "in_manifest": False} for f in files}
    print(f"Scanned {len(files)} file(s) in {args.driver_dir}")

    packages = build_packages(args, files, dist, inventory)
    for rel, entry in inventory.items():
        if not entry["in_manifest"] and "note" not in entry:
            entry["note"] = ("not in manifest: no .inf beside it" if rel.lower().endswith(".sys") else
                             "not in manifest: the schema and client have no installable format for this file type")
        print(f"  {'+' if entry['in_manifest'] else '-'} {entry['sha256'][:16]}  {entry['size']:>10}  {rel}"
              + (f"   ({entry['note']})" if entry.get("note") else ""))
    if not packages:
        print("build_manifest: nothing to publish (no valid .inf driver package found); no manifest written", file=sys.stderr)
        return 1

    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    stamp = lambda t: t.isoformat().replace("+00:00", "Z")
    key_id = trust.key_id(public)
    document = {"schema_version": "1.1", "sequence": args.sequence or int(time.time()),
                "generated": stamp(now), "expires": stamp(now + dt.timedelta(days=args.expires_days)),
                "publisher": {"name": args.publisher_name},
                "signing": {"algorithm": "ed25519", "key_id": key_id},
                "packages": packages}
    try:
        validate_against_schema(document)
        raw = (json.dumps(document, indent=2) + "\n").encode()
        signature = base64.b64encode(key.sign(raw))
        # Prove the result loads exactly as a client would load it, before writing anything.
        manifest_mod.load_manifest(raw, signature, trusted_keys={key_id: public}, check_rollback=False)
    except (BuildError, VerificationError) as exc:
        print(f"build_manifest: {exc}", file=sys.stderr)
        return 1

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(raw)
    sig_path = args.output.with_name(args.output.name + ".sig")
    sig_path.write_bytes(signature + b"\n")
    files_path = args.output.with_name(args.output.stem + ".files.json")
    files_path.write_text(json.dumps(inventory, indent=2) + "\n")

    print(f"\n{len(packages)} package(s) -> {args.output}  (sequence {document['sequence']}, expires {document['expires']})")
    print(f"signature  -> {sig_path}  (Ed25519, key id {key_id})")
    print(f"inventory  -> {files_path}")
    print(f"artifacts  -> {dist}  (upload to {args.url_prefix})")
    if key_id not in trust.PINNED_MANIFEST_KEYS:
        print(f"warning: key {key_id} is not pinned in src/core/trust.py; clients will refuse this manifest.\n"
              f"         Pin this public key: {public}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
