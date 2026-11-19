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

# Windows code signing (Authenticode)

The manifest key above protects *what gets installed*. Authenticode is separate: it signs
`driver-installer.exe`, `driver-installer-gui.exe` and `driver-installer-helper.exe`, so
Windows (UAC, SmartScreen, Smart App Control) can show who published them and detect tampering.

The build workflow signs automatically when two repository secrets exist
(Settings > Secrets and variables > Actions):

| Secret | Value |
|---|---|
| `WINDOWS_PFX_BASE64` | the `.pfx` (certificate + private key), base64-encoded |
| `WINDOWS_PFX_PASSWORD` | the `.pfx` password |

`tools/build_windows.py` then runs `signtool sign /fd SHA256 /tr http://timestamp.digicert.com
/td SHA256` on the three programs right after PyInstaller, before `BUILD-INFO.txt`, the zip and
`SHA256SUMS` are made, so every published hash is of the signed files. The decoded `.pfx` exists
only in a private temporary folder during that call and is overwritten and deleted afterwards,
also on failure. The CI job then checks each signature in the zip with `Get-AuthenticodeSignature`
(must be `Valid`, our certificate, timestamped) and `signtool verify` (SHA-256 digest), and the
release notes name the signer and thumbprint. Without the secrets (forks, local builds) the build
prints a notice and stays unsigned; with only one of them set, it fails.

## Getting the PFX secret

A certificate from a public CA (OV/EV code signing, or Azure Trusted Signing) is what makes
Windows trust the publisher on every PC. Note that CAs now issue new code-signing keys only on
hardware tokens or cloud HSMs, which cannot be exported as a `.pfx`; those need a different
signing step than this one. For testing, or for users who are told to trust your certificate,
a self-signed one works:

```powershell
$cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=Driver Installer (self-signed)' `
          -KeyAlgorithm RSA -KeyLength 3072 -HashAlgorithm SHA256 -NotAfter (Get-Date).AddYears(3) `
          -CertStoreLocation Cert:\CurrentUser\My
$pw = Read-Host 'PFX password' -AsSecureString
Export-PfxCertificate -Cert $cert -FilePath signing.pfx -Password $pw
Export-Certificate    -Cert $cert -FilePath driver-installer.cer       # public half, publish this
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$PWD\signing.pfx")) | Set-Clipboard
```

Paste the clipboard into `WINDOWS_PFX_BASE64` and the password into `WINDOWS_PFX_PASSWORD`
(or `base64 -w0 signing.pfx | gh secret set WINDOWS_PFX_BASE64`). Then delete `signing.pfx` and remove
the certificate from `Cert:\CurrentUser\My`, or keep it offline. On Linux:
`base64 -w0 signing.pfx`.

To sign a local build by hand: set the two environment variables and run
`py tools\build_windows.py`, or `py tools\codesign_windows.py <file.exe>...`.

## Trusting a self-signed certificate locally

Windows does not trust a self-signed certificate, so signatures show as "not trusted"
(`UnknownError`) until you add the public `.cer`. Check the thumbprint first: it must match the
one in the release notes and in `BUILD-INFO.txt`.

```powershell
(Get-PfxCertificate .\driver-installer.cer).Thumbprint
# elevated PowerShell:
Import-Certificate -FilePath .\driver-installer.cer -CertStoreLocation Cert:\LocalMachine\Root
Import-Certificate -FilePath .\driver-installer.cer -CertStoreLocation Cert:\LocalMachine\TrustedPublisher
Get-AuthenticodeSignature .\driver-installer-gui.exe      # Status: Valid
```

A trusted root can vouch for any program and any website, so only do this for a certificate you
created or got from someone you trust, and remove it when no longer needed
(`certlm.msc` > Trusted Root Certification Authorities). Trusting it does not satisfy Smart App
Control, which requires a certificate from a CA that Microsoft trusts.
