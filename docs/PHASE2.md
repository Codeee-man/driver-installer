# Phase 2: real execution

Phase 2 turns the proof of concept into a prototype that can really install.
It stays in Python (`src/core`), as requested; the Phase 1 recommendation to
move the core and the elevated helper to Rust before a public release still
stands.

## What runs with which rights

```
cli.py / gui.py  (ordinary user)                    helper --apply-plan  (administrator, one-shot)
  scan hardware                                        re-verify manifest signature against PINNED keys
  load + verify signed manifest                        copy each file into an admin-only directory,
  download -> size + SHA-256 -> publisher signature      re-hash the copy, re-check publisher signature
  show plan (dry run is the default)                   unpack, check catalog signer, locate the .inf
  confirm  ->  write plan.json  -- UAC / pkexec -->    restore point / snapshot
  read result file                 <-----------------  install, write result, exit
```

The helper treats the plan as untrusted input. A compromised front end can
pick which *signed* packages are installed; it cannot get anything unsigned,
altered or rolled back installed.

## Modules

| File | Role |
|---|---|
| `core/installer.py` | `pnputil /add-driver … /install`, `fwupdmgr install/update`, apt/dnf/pacman/zypper. `dry_run=True` by default; a real call raises `ElevationError` unless already elevated. |
| `core/restore.py` | `Checkpoint-Computer … DEVICE_DRIVER_INSTALL`, `timeshift --create`, `snapper create`. Reports created / existing / unavailable / failed. |
| `core/scanner_win.py` | Joins `Win32_PnPEntity`, `Win32_PnPSignedDriver`, `Win32_SystemDriver`. Transport is pluggable: `wmi` package, PowerShell CIM, or JSON fixtures. |
| `core/verifier.py` | SHA-256 gated download and staging copy, Authenticode (`Get-AuthenticodeSignature`, i.e. WinVerifyTrust) with exact publisher matching, GPG via `gpgv` against root-owned keyrings. |
| `core/elevation.py` | `IsUserAnAdmin`, `ShellExecuteExW` verb `runas`, `pkexec` / `sudo`. |
| `core/trust.py` | Pinned manifest keys. No flag or environment variable can add one. |
| `core/engine.py` | Orchestration, plan file, elevated helper logic. |
| `core/manifest.py`, `model.py`, `common.py`, `scanner_linux.py` | Manifest checks and matching, version comparison, audit log and command runner, Linux inventory. |

## Rules the code enforces

- **Dry run by default.** Only `--apply` (CLI, plus typing `install` or `--yes`)
  or the GUI's Install button plus its confirmation dialog leads to an install.
- **Everything is verified before anything changes.** Hash, publisher
  signature, archive unpacking and catalog signer are all checked before the
  restore point is requested.
- **No restore point, no install**, unless the user explicitly agrees
  (second prompt) or passes `--allow-no-snapshot`. Exception, as specified:
  on Linux with neither Timeshift nor snapper installed the helper logs a
  warning and continues. A package with `snapshot_required: true` can never be
  installed without one.
- **Windows restore points:** Windows silently skips creation if one was made
  in the last 24 hours; that is reported as `existing`, not as an error.
  "System Restore is disabled" is reported with the fix.
- **Vendor `.exe` installers are not supported** on purpose: their silent
  switches differ per vendor and they run arbitrary code as administrator.
  Windows packages are INF driver packages (`.cab` or `.zip`).

## Setting up a signing key

`core/trust.py` ships with no key, so every manifest is refused until one is
pinned:

```
python tools/keygen.py --out ~/safedriver-signing.key --pin
python tools/sign_manifest.py --key ~/safedriver-signing.key manifest.json
python src/cli.py update --all --manifest manifest.json            # dry run
python src/cli.py update --all --manifest manifest.json --apply    # install
```

## What has and has not been exercised

Tested (217 tests, Linux): manifest pinning/expiry/rollback, downloads against
a real loopback server, real GPG signatures, WMI parsing from fixtures,
version comparison, command construction, exit-code mapping, restore-point
logic, the full dry-run / elevate / helper flow with a fake command runner, the
GUI install dialog flow, and the helper as a real `python -I` subprocess.

Not exercised: anything on a real Windows machine (PowerShell scripts,
`ShellExecuteExW`, `icacls`, `pnputil`, System Restore), and real `pkexec`,
`fwupdmgr`, Timeshift, snapper or package-manager runs. Treat the first run on
real hardware as a test: use a VM or a machine you can re-image.

## Discovery and the BYOVD check (added after Phase 2)

- `core/discovery/ms_catalog.py`, `core/discovery/linux_lvfs.py`: updates without a manifest.
  A discovered package has no pinned-key signature behind it, so the helper applies fixed
  rules instead: a catalog driver must carry a `.cat` signed by Microsoft's hardware
  publisher; a distro package must be one the helper's own run of the distro tool recommends.
- `core/security/loldrivers.py`: every `.sys` is checked against the live LOLDrivers feed,
  by the front end after download and again by the helper before the restore point.
  A hit aborts the whole plan. An unreachable feed stops the install until the user agrees.
- Tests use loopback mock servers; catalog discovery and download were also checked against the live
  catalog from a Windows runner.

## Known gaps

- Un-installed, the helper is `python src/helper_main.py` in your checkout (or a portable
  `DriverInstaller.exe`), which your own account can modify; the tool warns each time.
  `DriverInstaller-Setup.exe`, the .deb and `tools/install_helper.sh` / `.ps1` install it to an
  administrators-only path, and the core then prefers it. Windows builds are Authenticode-signed
  only when the repository has the signing secrets (docs/SIGNING.md).
- fwupd is driven through `fwupdmgr`, not D-Bus.
- Windows Update drivers that the public catalog cannot serve are fetched through the Windows
  Update Agent; that path is tested with a stand-in for the agent, not yet on physical hardware.
- `expand.exe` output is not re-checked for path traversal (zip extraction is).
