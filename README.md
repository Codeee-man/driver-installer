# driver-installer (SafeDriver)

Open-source driver and firmware updater for Windows and Linux. No ads, no
telemetry, no background service. Working prototype: real installation behind
a dry-run default.

```
pip install cryptography PySide6 pytest
python -m pytest -q                                  # 249 tests, no admin rights or internet needed

python src/cli.py scan                               # hardware vs. manifest (table, or --json)
python src/cli.py check --notify                     # exit 0 up to date, 1 updates, 2+ error
python src/cli.py update --all                       # download, verify, print the plan (dry run)
python src/cli.py update --all --apply -y            # unattended install
python src/cli.py gui --demo                         # GUI with fake packages; never installs
```

Without a manifest the tool discovers updates itself: Microsoft Update Catalog on Windows
(hardware IDs are sent to Microsoft; `--no-discover` turns it off), fwupd/LVFS and the
distro's driver tool on Linux. Every Windows driver package is checked against the
LOLDrivers list of known vulnerable drivers before install.

Before real use:

1. Pin a signing key and sign your manifest: `tools/pin_key.sh`, see `docs/SIGNING.md`.
2. Install the protected helper: `sudo tools/install_helper.sh [--with-timer]`
   (Windows: `tools\install_helper.ps1` from an elevated PowerShell). Without it the
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
