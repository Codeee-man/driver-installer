"""Trust anchors compiled into the application.

The manifest is trusted only if its detached Ed25519 signature verifies under
one of the keys below. There is deliberately no command-line flag or
environment variable that adds a key: the elevated helper must never accept a
trust anchor from the unprivileged process that launched it.

No release key exists yet, so this ships EMPTY and every manifest is refused
until a key is pinned:

    python tools/keygen.py --pin        # creates a key pair and pins the public half here

Keep the private key offline. Rotate by pinning the new key in a release
before retiring the old one.
"""
from __future__ import annotations

import hashlib

# key_id -> hex of the raw 32-byte Ed25519 public key
PINNED_MANIFEST_KEYS: dict[str, str] = {
    # keygen-insert (tools/keygen.py --pin adds a line below this marker)
}

# Directories holding the OpenPGP keys of package publishers. Only root-owned,
# non-world-writable files are used. The manifest pins which fingerprint must
# have signed each package; the key material itself must come from here.
GPG_KEYRING_DIRS = [
    "/usr/share/safedriver/keyrings",
    "/usr/share/keyrings",
    "/etc/apt/trusted.gpg.d",
    "/etc/apt/keyrings",
    "/etc/pki/rpm-gpg",
    "/usr/share/pacman/keyrings",
]


# Driver packages found through Microsoft Update Catalog discovery have no entry in a signed
# manifest. Their security catalog (.cat) must instead be signed by Microsoft's hardware
# publisher, which is how every WHQL-certified or attestation-signed driver is released.
MS_WHQL_SUBJECT = "O=Microsoft Corporation, CN=Microsoft Windows Hardware Compatibility Publisher"
# Drivers Windows Update offers this PC: OEM drivers carry the hardware publisher's signature;
# Microsoft's own drivers (e.g. audio effects such as Voice Clarity) are signed "Microsoft
# Windows". Either must be an exact RDN match on a signature Windows reports as Valid.
MS_WINDOWS_SUBJECT = "O=Microsoft Corporation, CN=Microsoft Windows"
WINDOWS_UPDATE_SUBJECTS = [MS_WHQL_SUBJECT, MS_WINDOWS_SUBJECT]


def key_id(pubkey_hex: str) -> str:
    return hashlib.sha256(bytes.fromhex(pubkey_hex)).hexdigest()[:16]
