# driver-installer (SafeDriver)

Open-source driver and firmware updater for Windows and Linux. No ads, no
telemetry, no background service. Working prototype: real installation behind
a dry-run default.

```
pip install cryptography PySide6 pytest
python -m pytest -q                                  # 278 tests, no admin rights or internet needed

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

Releases: push a tag like `v1.0.0` and `.github/workflows/build.yml` tests on Windows and Linux,
then attaches `DriverInstaller-Setup.exe`, `DriverInstaller-Windows-Portable.zip`, a `.deb` and an
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

Layout:

- `src/core/` - engine: scanner, verifier, restore points, installer, elevation
- `src/core/discovery/` - Microsoft Update Catalog, fwupd/LVFS and distro driver discovery
- `src/core/security/` - LOLDrivers (BYOVD) blocklist check
- `src/cli.py`, `src/ui/` - front ends (never elevated); `src/helper_main.py` - the elevated helper
- `schema/` - manifest schema 1.1 and an example
- `tools/` - `install_helper.sh|.ps1`, `pin_key.sh`, `keygen.py`, `sign_manifest.py`
- `contrib/` - systemd user units, polkit policy
- `tests/` - pytest suite with recorded WMI fixtures
- `docs/` - `ARCHITECTURE.md`, `PHASE2.md`, `SIGNING.md`; `TESTING_WINDOWS.md` at the top level
- `poc/` - Phase 1 single-file proof of concept, superseded by `src/`

The Matrix theme uses the bundled VT323 font (SIL Open Font License, `src/ui/assets/fonts/VT323-OFL.txt`).
