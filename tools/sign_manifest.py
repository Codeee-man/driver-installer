#!/usr/bin/env python3
"""Sign a manifest: writes <manifest>.sig (base64 Ed25519 over the exact file bytes).

    python tools/sign_manifest.py --key ~/safedriver-signing.key manifest.json

The key is the hex file tools/keygen.py writes or an Ed25519 PEM (the same loader as
tools/build_manifest.py, which builds and signs a manifest from a driver folder in one go).
Re-sign after every edit: changing a single byte invalidates the signature.
"""
import argparse
import base64
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))
from core import manifest as manifest_mod, trust  # noqa: E402
from build_manifest import BuildError, load_signing_key  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--key", type=Path, required=True)
    ap.add_argument("manifest", type=Path)
    args = ap.parse_args(argv)
    try:
        key, pub = load_signing_key(args.key.expanduser())
    except (BuildError, OSError) as exc:
        print(f"sign_manifest: {exc}", file=sys.stderr)
        return 2
    raw = args.manifest.read_bytes()
    doc = json.loads(raw)
    for pkg in doc.get("packages", []):
        manifest_mod.validate_package(pkg)          # refuse to sign something clients would reject
    kid = trust.key_id(pub)
    if doc.get("signing", {}).get("key_id") != kid:
        print(f"note: manifest signing.key_id is {doc.get('signing', {}).get('key_id')}, this key is {kid}")
    if kid not in trust.PINNED_MANIFEST_KEYS:
        print("warning: this key is not pinned in src/core/trust.py; clients will refuse the manifest")
    sig = args.manifest.with_name(args.manifest.name + ".sig")
    sig.write_bytes(base64.b64encode(key.sign(raw)) + b"\n")
    print(f"signed {args.manifest} -> {sig}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
