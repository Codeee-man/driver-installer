# Signing key setup

SafeDriver accepts a manifest only if it is signed by an Ed25519 key pinned in
`src/core/trust.py`. The repository ships with no key, so nothing can be
installed until you pin one. There is no flag or environment variable that
adds a key at run time.

## Linux / macOS (signing machine)

```
tools/pin_key.sh                       # key -> ~/.config/driver-installer/signing.key, public half pinned
python3 tools/sign_manifest.py --key ~/.config/driver-installer/signing.key manifest.json
sudo tools/install_helper.sh           # the installed helper carries its own copy of trust.py
sudo install -D -m 0644 manifest.json manifest.json.sig -t /etc/driver-installer/
driver-installer check
```

## Windows

```
py tools\keygen.py --out "$env:USERPROFILE\safedriver-signing.key" --pin
py tools\sign_manifest.py --key "$env:USERPROFILE\safedriver-signing.key" manifest.json
powershell -ExecutionPolicy Bypass -File tools\install_helper.ps1     # elevated prompt
```

## Rules

- `pin_key.sh` and `keygen.py` refuse to overwrite an existing key file.
- Re-sign after every edit of the manifest; one changed byte invalidates the signature.
- Re-run `install_helper` after pinning or rotating: the helper trusts the keys
  it was installed with, not the ones in your checkout.
- Commit `src/core/trust.py`. Never commit the key file (`*.key` is in `.gitignore`).
- Rotation: pin the new key next to the old one, ship that release, start
  signing with the new key, then remove the old line in a later release.
- For a real release the private key belongs on an offline machine or a
  hardware token, not on the build machine.
