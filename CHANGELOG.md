# Changelog

All notable changes to Driver Installer (SafeDriver). Versions follow `vMAJOR.MINOR.PATCH` tags;
each tag's GitHub Release shows its section from this file above the downloads
(`tools/changelog.py`). Add new entries under **Unreleased**; rename it to the version when you tag.

## [Unreleased]

### Added
- **[ SETTINGS ]** replaces the theme toggle in the header: a compact dialog with the accent
  colour (Matrix Green `#00FF66`, Vivid Orange `#FF6B1A`, Cyan `#00E5FF`, Amber `#FFB000`,
  Silver `#E4E8EF`), the font (VT323, Mono, Sans) and "Check for updates on startup". Changes
  apply at once to the whole window (borders, title, badges, buttons, progress bar, LOG,
  dialogs) and are saved in `ui.json`. Full / Partial / None stay green / amber / red whatever
  the accent.
- **Update available.** When enabled (the default), the window asks GitHub's
  `releases/latest` API once per start, in the background (3 s timeout, silent when offline or
  rate-limited, only the program name and version are sent). If a newer release exists, an
  UPDATE AVAILABLE button appears in the header, without a version number; it opens the
  release page in the browser. There is never a popup.
- `tools/screenshots.py` renders the README screenshots headlessly.

### Changed
- **One design.** The separate Clean theme and `gui --theme` are gone; the Matrix terminal look
  (sharp 1 px borders, capitals and brackets) is the only one, restyled by the Settings presets.
  An old `"theme"` entry in `ui.json` is ignored.
- **Identical devices are shown once.** Windows lists every logical CPU as its own device, so a
  16-thread CPU appeared 16 times. Devices with the same name, model (hardware ID), driver
  package (INF), installed version and state are now one row with a subtle `×16` (`x16` in
  `scan`, `instances` in `scan --json`). The merged entry keeps every instance ID and hardware
  ID, so update matching and `pnputil` still cover all of them.

### Fixed
- **No more false "administrator rights … UAC prompt was declined" message when Setup is first
  started.** Inno Setup's loader starts without rights (`asInvoker`) and restarts itself
  elevated; on a first launch, antivirus interception of the freshly downloaded file could break
  that restart, and Setup reported a declined prompt that never appeared. The build now switches
  `DriverInstaller-Setup.exe`'s manifest to `requireAdministrator` (in place, before signing), so
  Windows shows the UAC prompt itself before Setup runs. No `.iss` directive can do this:
  `PrivilegesRequired=admin` was already set. The custom message is gone, and "Start Driver
  Installer" on the last page now goes through Explorer so the program still runs without admin
  rights. `DriverInstaller.exe` is unchanged (`asInvoker`).
- **Log times are local.** The LOG drawer, the audit log and the installer's `.log` files use the
  computer's time zone (with its offset, e.g. `+01:00`), not UTC; older UTC entries are shown in
  local time too.
- **Drivers that `pnputil` added to the driver store (exit code 259) show as INSTALLED** in green,
  not as a dimmed "Up to date" row, and move to the top with the other results. The reason
  ("pnputil 259: no device switched to it now …") is in the row's tooltip and in LOG, which now
  lists every install result, not only failures.
- **Localized `pnputil` messages are readable.** Output is decoded as UTF-8, else in the Windows
  ANSI code page (`GetACP`, cp1250 on Czech Windows, which `pnputil` uses) or the OEM one
  (`GetOEMCP`, cp852), whichever reads as text: "Systém nemůže nalézt uvedený soubor." instead of
  "SystÚm nem¨×e …".

## [1.1.5] - 2026-11-23

### Fixed
- **Scans no longer stall on Windows Update drivers.** Without admin rights, Windows refuses to
  copy a downloaded update out of its cache (`E_ACCESSDENIED`), after a 20-40 s download per
  driver. The scan no longer tries: drivers that Windows Update offers this PC and that the public
  catalog cannot serve are shown with their checks "checked by the installer" (`»` in the `(?)`),
  counting as Full, because the installer refuses them unless every check passes.
- **Live install progress.** While the installer runs as administrator, the window follows its
  log every 300 ms: the status line shows the current step and driver ("Installing (2/5): …"),
  and LOG gets the `[admin]` lines as they happen, not after it exits.
- **OEM-signed and Insider flight-signed Windows Update drivers.** For a package the installer
  received from the Windows Update Agent itself, Windows Update is the trust anchor: any valid
  catalog signature is accepted (e.g. HP Inc.), and an untrusted-root signature (WDK test
  certificates on Windows Insider builds) is logged as a warning and left to Windows' own driver
  signing check in `pnputil`. Unsigned or tampered catalogs are still refused, and LOLDrivers
  still checks every `.sys`. Catalog and manifest packages keep their pinned publishers.
- **Multi-file Windows Update drivers** (e.g. HP SoftwareComponent, `Maintenance.cab`, 83 files):
  cabinets are unpacked with Windows' `tar.exe`, keeping their folders (`expand.exe` as fallback),
  and all parts of an update share one tree, so the `.inf`'s relative paths resolve. If `pnputil`
  still reports a missing file (rc 2), the update is installed with the Windows Update Agent's
  installer instead.
- Localized tool output (e.g. Czech `pnputil` messages) is decoded with the console code page
  instead of turning into `?` characters.

## [1.1.4] - 2026-11-20

### Changed
- **Clean theme redesigned: Warm Carbon & Vivid Orange.** Carbon surfaces, one orange accent
  (`#FF6B1A`) for the "Download and Install" button, the progress bar, checked boxes and focus;
  semantic pills: orange-tinted "To update", slate "Up to date", green Full, amber Partial,
  coral None. Rounded geometry throughout: 12 px table and log, 8 px buttons, full pills,
  5 px checkboxes (now with a tick), 4 px progress bar. Row highlights are clipped to the
  table's rounded corners.
- **Matrix layout polish.** `LOG`, `[ MATRIX ]` and `RESCAN` share one height, padding and a
  1px terminal border with hover states; row spinners line up in one column, centred on their
  pill, and no longer bob between frames.

### Fixed
- **Windows Update drivers marked Partial were all refused by the installer** ("Blocked", no
  reason in LOG). As administrator, the installer now takes whatever the Windows Update Agent
  hands over (a driver cabinet without a `.cab` name, a named `.cab`, or loose
  `.inf`/`.cat`/`.sys` files) and builds the driver folder from it, instead of refusing anything
  not named `*.cab`. LOLDrivers, the catalog signature and `pnputil /add-driver … /install` then
  run on that folder.
- Microsoft's own drivers from Windows Update (e.g. Voice Clarity) are signed "Microsoft Windows",
  not by the hardware publisher; both signers are accepted for Windows Update items (exact match,
  valid Microsoft signature). Catalog-only drivers still need the hardware publisher.
- **The installer's log reaches the window.** Everything the elevated run does is recorded in its
  result and live in `results/<plan>.log` (kept even if it crashes), and replayed into LOG marked
  `[admin]`. Every blocked row says which step refused it and why (status line, LOG, tooltip), and
  LOG opens by itself when something was not installed.
- Long status messages end in "…" (full text in the tooltip) and keep a fixed gap before the
  `1 / 5` counter, instead of being cut mid-word against it.
- The window starts with focus in the device list, so `LOG` no longer looks highlighted.
- **Install confirmation no longer overflows the screen.** With many drivers selected, the
  "Download and Install" dialog grew past the screen and hid its buttons. It now stays within
  580 px (and 75 % of the screen): the driver list and the "partially verified" notes each scroll in
  their own framed box, every driver is listed instead of the first 8 (or 5), and Install / Cancel
  are pinned below the boxes. Same wording, buttons and themes as before.

## [1.1.3] - 2026-11-20

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
- `tools/changelog.py` prints UTF-8 on Windows consoles (it failed on code pages such as cp1250).

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

[Unreleased]: https://github.com/Codeee-man/driver-installer/compare/v1.1.4...HEAD
[1.1.4]: https://github.com/Codeee-man/driver-installer/compare/v1.1.3...v1.1.4
[1.1.3]: https://github.com/Codeee-man/driver-installer/compare/v1.1.2...v1.1.3
[1.1.2]: https://github.com/Codeee-man/driver-installer/compare/v1.1.1...v1.1.2
[1.1.1]: https://github.com/Codeee-man/driver-installer/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/Codeee-man/driver-installer/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/Codeee-man/driver-installer/releases/tag/v1.0.0
