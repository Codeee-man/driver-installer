#!/usr/bin/env python3
"""Create an Ed25519 manifest signing key and (optionally) pin its public half.

    python tools/keygen.py --out ~/safedriver-signing.key --pin

The private key is written with owner-only permissions and is never placed in
the repository. --pin inserts the public key into src/core/trust.py, which is
the only place the application takes trust anchors from.
"""
import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from core import trust  # noqa: E402

MARKER = "# keygen-insert"


def main() -> int:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", type=Path, default=Path("safedriver-signing.key"))
    ap.add_argument("--pin", action="store_true", help="add the public key to src/core/trust.py")
    ap.add_argument("--trust-file", type=Path, default=ROOT / "src" / "core" / "trust.py")
    args = ap.parse_args()
    out = args.out.expanduser()
    if out.exists():
        print(f"{out} already exists; refusing to overwrite a signing key", file=sys.stderr)
        return 1
    if ROOT in out.resolve().parents:
        print("warning: writing a private key inside the repository; do not commit it", file=sys.stderr)
    key = Ed25519PrivateKey.generate()
    raw = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(raw.hex() + "\n")
    kid = trust.key_id(pub)
    print(f"private key : {out}\npublic key  : {pub}\nkey id      : {kid}")
    if args.pin:
        text = args.trust_file.read_text()
        if MARKER not in text:
            print("marker not found in trust.py; add the key by hand", file=sys.stderr)
            return 1
        head, sep, tail = text.partition(MARKER)
        line_end = tail.index("\n") + 1
        args.trust_file.write_text(head + sep + tail[:line_end] + f'    "{kid}": "{pub}",\n' + tail[line_end:])
        print(f"pinned in   : {args.trust_file}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
