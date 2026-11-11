#!/usr/bin/env python3
"""Sign a manifest: writes <manifest>.sig (base64 Ed25519 over the exact file bytes).

    python tools/sign_manifest.py --key ~/safedriver-signing.key manifest.json

Re-sign after every edit: changing a single byte invalidates the signature.
"""
import argparse
import base64
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from core import manifest as manifest_mod, trust  # noqa: E402


def main() -> int:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--key", type=Path, required=True)
    ap.add_argument("manifest", type=Path)
    args = ap.parse_args()
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(args.key.expanduser().read_text().strip()))
    pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
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
