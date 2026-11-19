# Changelog

All notable changes to Driver Installer (SafeDriver). Versions follow `vMAJOR.MINOR.PATCH` tags;
each tag's GitHub Release shows its section from this file above the downloads
(`tools/changelog.py`). Add new entries under **Unreleased**; rename it to the version when you tag.

## [Unreleased]

### Fixed
- **Windows Setup elevation.** `DriverInstaller-Setup.exe` now asks for administrator rights only
  through the native UAC prompt and never offers a per-user install
  (`PrivilegesRequired=admin`, overrides disabled). If Windows does not grant the rights, the
  message says why (prompt declined, or the account may not elevate) and points to the portable
  zip, instead of a bare "administrator privileges required".
- After copying, Setup no longer starts PowerShell (which policies can block); download marks are
  removed directly. A running Driver Installer is closed first, and the folder lock-down
  (Administrators/SYSTEM full control, Users read & execute) is retried before Setup reports a
  failure.
- `DriverInstaller.exe` itself still starts without a prompt (`asInvoker`) and elevates only to
  install drivers.

### Added
- `CHANGELOG.md`; release builds put the matching section into the GitHub Release notes.

## [1.1.2] - 2026-11-19

### Fixed
- **"Verification: None" on Windows Update drivers** such as OEM application drivers. The
  Microsoft Update Catalog answers `302 -> ErrorInline.aspx` for updates it has no public copy
  of; the download dialog now detects and names that redirect instead of reading the error page
  as an empty result.
- Such drivers are fetched through the Windows Update Agent itself and then checked like any other
  (SHA-256, LOLDrivers, Microsoft driver signature), so they can reach **Full**. When Windows lets
  only administrators download them, they show **Partial** with both reasons, and the elevated
  installer downloads them and runs every check before installing.
- Failed checks show the real reason ("not reached: SHA-256 integrity failed (…)") instead of
  "not reached: an earlier step failed", in the `(?)` popover (now also on **None** rows) and in
  the LOG drawer.

### Changed
- One unpacker for driver packages; helper selection moved to `core/elevation.py`; build tools
  share one Windows tool finder and PowerShell runner. Dead code removed.
- Removed the Phase 1 `poc/` prototype; `TESTING_WINDOWS.md` moved to `docs/`; README layout updated.

## [1.1.1] - 2026-11-19

### Added
- **Progressive scanning.** Every device appears as soon as the hardware is enumerated, then each
  row settles in place when its own lookup finishes: updates move to the top, the rest become
  "Up to date".
- Per-row loading spinners (terminal spinner in Matrix, rotating arc in Clean) that stop, and use
  no CPU, once every row is final.
- Progress bar beside the status line: pulsing while nothing can be counted (enumeration,
  Windows Update search, install), counting devices and downloads otherwise.

### Fixed
- Rows whose lookup never finished show "Not checked" after a failed scan instead of spinning.

## [1.1.0] - 2026-11-19

### Added
- **Windows Update discovery** through the Windows Update Agent, alongside the Microsoft Update
  Catalog; the newer driver per device wins.
- **One Windows program**, `DriverInstaller.exe`: GUI on double-click, CLI with arguments,
  elevated helper with `--apply-plan`.
- **`DriverInstaller-Setup.exe`** (Inno Setup): installs to `C:\Program Files\Driver Installer`
  with an administrators-only ACL, Start menu shortcut, optional `driver-installer` command on PATH.
- Optional **Authenticode signing** of the program, Setup and uninstaller when the
  `WINDOWS_PFX_BASE64`/`WINDOWS_PFX_PASSWORD` secrets are set; CI verifies the signatures.
- `--debug` and the LOG drawer explain every discovery step and why each result was skipped;
  `tools/diagnose_windows.ps1` finds out why Windows refuses to start the program.
- Clean theme redesigned as Metallic Monochrome (obsidian and brushed silver).

### Fixed
- Catalog drivers no longer fail the signature check on real Windows (PowerShell 7's module path
  broke Windows PowerShell 5.1).
- Catalog lookup examines the whole first results page, falls back from the full to the base
  hardware ID, and respects the Windows release a package is built for.

### Changed
- Release assets are `DriverInstaller-Setup.exe` and `DriverInstaller-Windows-Portable.zip`
  (previously `driver-installer-windows.zip` with three programs).

## [1.0.0] - 2026-11-16

First release.

- Scan → Review → Apply driver and firmware updater for Windows (WMI, pnputil, System Restore)
  and Linux (lspci/lsusb, fwupd/LVFS, distribution driver tools, Timeshift/snapper).
- Every package is SHA-256 verified against an Ed25519-signed manifest with pinned keys, or
  discovered from the Microsoft Update Catalog and checked against Microsoft's driver signature;
  Authenticode and GPG publisher checks; LOLDrivers (BYOVD) blocklist check before install.
- Unprivileged GUI and CLI (`scan`, `check`, `update`, `--dry-run` by default); one-shot elevated
  helper that re-verifies everything; restore point before installing; hash-chained audit log.
- PySide6 window with Matrix and Clean themes, background verification, "(?)" check details.
- Tools for keys, manifest signing (`tools/builder.py`), and protected helper installation;
  systemd timer for weekly checks.
- Release builds: Windows zip, `.deb` and AppImage, with SHA-256 sums and download links.

[Unreleased]: https://github.com/Codeee-man/driver-installer/compare/v1.1.2...HEAD
[1.1.2]: https://github.com/Codeee-man/driver-installer/compare/v1.1.1...v1.1.2
[1.1.1]: https://github.com/Codeee-man/driver-installer/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/Codeee-man/driver-installer/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/Codeee-man/driver-installer/releases/tag/v1.0.0
