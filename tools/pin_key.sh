#!/bin/sh
# Create a manifest signing key and pin its public half into src/core/trust.py.
#
#   tools/pin_key.sh [KEYFILE]      default: ~/.config/driver-installer/signing.key
#
# Wraps `python3 tools/keygen.py --pin`. Run as your normal user, never with sudo:
# the private key should belong to you and stay out of the repository.
# See docs/SIGNING.md for the full workflow.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
KEY=${1:-${XDG_CONFIG_HOME:-$HOME/.config}/driver-installer/signing.key}
PYTHON=${PYTHON:-python3}

[ "$(id -u)" -ne 0 ] || { echo "pin_key: run as your normal user, not root" >&2; exit 1; }
"$PYTHON" -c 'import cryptography' 2>/dev/null || { echo "pin_key: pip install cryptography" >&2; exit 1; }
if [ -e "$KEY" ]; then
    echo "pin_key: $KEY already exists. Keep using it, or pass a different KEYFILE to rotate." >&2
    exit 1
fi
if grep -Eq '^ +"[0-9a-f]{16}": "[0-9a-f]{64}",' "$ROOT/src/core/trust.py"; then
    echo "note: src/core/trust.py already pins a key; the new one is added alongside it (rotation)."
fi

mkdir -p -- "$(dirname -- "$KEY")"
chmod 700 -- "$(dirname -- "$KEY")"
"$PYTHON" "$ROOT/tools/keygen.py" --out "$KEY" --pin

cat <<EOF

Next:
  1. Back up $KEY somewhere offline. Anyone holding it can sign manifests your installs will trust.
  2. Sign a manifest:    $PYTHON tools/sign_manifest.py --key "$KEY" manifest.json
  3. Reinstall the protected helper so it carries the new key:
                         sudo tools/install_helper.sh
  4. Commit src/core/trust.py (public key only). Never commit the key file.
EOF
