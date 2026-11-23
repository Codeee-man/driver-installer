# driver-installer (SafeDriver)

Open-source driver and firmware updater for Windows and Linux. No ads, no
telemetry, no background service. Working prototype: real installation behind
a dry-run default.

```
pip install cryptography PySide6 pytest
python -m pytest -q                                  # 414 tests, no admin rights or internet needed

python src/cli.py scan                               # hardware vs. manifest (table, or --json)
python src/cli.py check --notify                     # exit 0 up to date, 1 updates, 2+ error
python src/cli.py update --all                       # download, verify, print the plan (dry run)
python src/cli.py update --all --apply -y            # unattended install
python src/cli.py gui --demo                         # GUI with fake packages; never installs
python src/cli.py gui --theme clean                  # "matrix" (default) or "clean"; the in-app toggle is remembered
```

Without a manifest the tool discovers updates itself: on Windows, Windows Update (the drivers
Windows offers this PC) plus the Microsoft Update Catalog searched by hardware ID (hardware IDs
are sent to Microsoft; `--no-discover` turns it off); on Linux, fwupd/LVFS and the distro's
driver tool. `--debug` (or LOG in the window) shows every step: devices scanned, queries,
results, and why each result was skipped. Every Windows driver package is checked against the
LOLDrivers list of known vulnerable drivers before install.

Releases: push a tag `vMAJOR.MINOR.PATCH` (the current line is `v1.1.x`; the next is `v1.1.4`; describe it under Unreleased in `CHANGELOG.md` first) and
`.github/workflows/build.yml` tests on Windows and Linux, installs the Windows build as a standard
user, then attaches `DriverInstaller-Setup.exe`, `DriverInstaller-Windows-Portable.zip`, a `.deb` and an
`.AppImage` (plus `SHA256SUMS`) to a published release. Build locally with
`python tools/build_linux.py all` or `py tools\build_windows.py` (the installer needs Inno Setup 6).

On Windows there is one program, `DriverInstaller.exe`: double-click it for the window; give it
arguments (`DriverInstaller.exe scan --json > scan.json`) for the CLI; it elevates itself for
installs. `DriverInstaller-Setup.exe` installs it to `C:\Program Files\Driver Installer`, locked so
only administrators can change it, with an optional `driver-installer` command on PATH. Because
the program is windowed, an interactive `cmd` prompt does not wait for it; use the
`driver-installer` command, `start /wait DriverInstaller.exe ...`, or redirect the output.
Both are Authenticode-signed when the repository has the `WINDOWS_PFX_BASE64`/`WINDOWS_PFX_PASSWORD`
secrets (see `docs/SIGNING.md`); otherwise unsigned.

Before real use:

1. Pin a signing key and sign your manifest: `tools/pin_key.sh`, see `docs/SIGNING.md`.
2. Install the protected helper: `sudo tools/install_helper.sh [--with-timer]`
   (Windows: `DriverInstaller-Setup.exe`; from a checkout, `tools\install_helper.ps1`). Without it the
   tool still works but warns, because it elevates code your user account can edit.
3. Optional weekly check: `systemctl --user enable --now driver-installer.timer`.

Windows Update drivers that the public catalog cannot serve (its download dialog answers
`302 -> ErrorInline.aspx`, common for OEM drivers) are not downloaded during the scan: Windows lets
only administrators copy them out of its cache. Their checks show as "checked by the installer"
(`»` in the `(?)`), and the installer, as administrator, has the Windows Update Agent download them,
runs LOLDrivers on every `.sys` and requires a valid signature on every catalog before `pnputil`
runs, refusing the update otherwise. While it works, the status line and LOG follow it live
(`[admin]` lines). Every failed check shows its real reason in the `(?)` next to the badge and in LOG.

Layout:

```
src/
  cli.py, ui/                 front ends (never elevated); gui.py, demo.py
  windows_main.py             DriverInstaller.exe: GUI, CLI and --apply-plan helper in one program
  helper_main.py              the elevated helper (--apply-plan <plan.json> only)
  core/
    engine.py                 scan -> discover -> download + verify -> plan -> helper
    scanner_win.py, scanner_linux.py   hardware inventory (WMI, lspci/lsusb, fwupd)
    discovery/                Windows Update Agent, Microsoft Update Catalog, LVFS/distro tools
    verifier.py               HTTPS fetches, SHA-256 gated downloads, Authenticode, GPG
    security/loldrivers.py    LOLDrivers (BYOVD) blocklist
    installer.py              unpack, pnputil / fwupd / package manager
    elevation.py              which helper to elevate, UAC / pkexec / sudo
    restore.py, manifest.py, trust.py, model.py, common.py, diagnostics.py
packaging/windows/            PyInstaller spec, Inno Setup script (DriverInstaller-Setup.exe)
tools/
  build_windows.py, build_linux.py, build_common.py   release builds (zip + Setup.exe, .deb + AppImage)
  codesign_windows.py         Authenticode signing with signtool (docs/SIGNING.md)
  diagnose_windows.ps1        why Windows refuses to start the program (read-only)
  install_helper.sh|.ps1      protected helper from a source checkout
  pin_key.sh, keygen.py, sign_manifest.py, builder.py   manifest keys and signing
  changelog.py                CHANGELOG.md section for a release's notes
schema/                       manifest schema 1.1 and an example
contrib/                      systemd user units, polkit policy, desktop file, icons
docs/                         ARCHITECTURE.md, PHASE2.md, SIGNING.md, TESTING_WINDOWS.md
tests/                        pytest suite with recorded WMI fixtures and loopback HTTP servers
.github/workflows/            ci.yml (tests on push), build.yml (release builds on v* tags)
```

The Matrix theme uses the bundled VT323 font (SIL Open Font License, `src/ui/assets/fonts/VT323-OFL.txt`).
