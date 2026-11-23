# SafeDriver (`driver-installer`): architecture

A driver and firmware updater with no ads, no telemetry, no bundled extras and no process left
running after exit. This document describes the implementation in `src/`; the README has the
file layout and the commands.

## 1. Design principles

1. **Index, don't host.** SafeDriver never repackages or mirrors drivers. A manifest is a signed
   *index* that points at the vendor's or distro's own download and records the expected
   SHA-256 and signer. Private driver databases are the root of both the trust problem and the
   bad-driver problem of Driver Booster-style tools.
2. **Prefer the platform's own channel.** Windows Update and the Microsoft Update Catalog on
   Windows; LVFS via fwupd and the distro's driver tool on Linux. A manifest covers what those miss.
3. **Fail closed.** Unsigned or expired manifest, hash mismatch, bad Authenticode/GPG signature,
   a known vulnerable driver, missing snapshot: the update does not proceed.
4. **Least privilege, short-lived.** The window, CLI and scanner run unprivileged. A one-shot
   helper is elevated (UAC / pkexec / sudo) only to apply a plan, and exits when it finishes. No
   service, no scheduled task, no tray icon, no autostart.
5. **Everything is logged locally.** The network requests are manifest fetches, discovery
   queries, package downloads, the LOLDrivers list and (if enabled) one release check; each is
   in the audit log, and none carries data beyond what the request itself needs.

## 2. What runs with which rights

```
cli.py / ui/ / DriverInstaller.exe  (user)         helper --apply-plan  (administrator, one-shot)
  scan hardware, merge identical devices              re-verify the manifest against PINNED keys
  discover: manifest, Windows Update, Catalog,        copy each file into an admin-only directory,
    fwupd/LVFS, distro tool                             re-hash the copy, re-check its signer
  download -> size + SHA-256 -> publisher signature   unpack, check catalog signer, locate the .inf
  LOLDrivers check                                    LOLDrivers check again
  show plan (dry run is the default)                  restore point / snapshot
  confirm -> write plan.json -- UAC / pkexec -->      install, write <plan>.json + live <plan>.log
  read result (tailing the .log for progress) <----   exit
```

The helper treats the plan as untrusted input. A compromised front end can choose which
*verified* packages are installed; it cannot get anything unsigned, altered or rolled back
installed, and the helper re-hashes every file itself, so a file swapped between download and
install (TOCTOU) is refused.

On Windows there is one program, `DriverInstaller.exe` (manifest `asInvoker`): without
arguments the window, with arguments the CLI, with `--apply-plan` the helper. `DriverInstaller-Setup.exe`
(manifest `requireAdministrator`) installs it to an administrators-only folder, which the core
then prefers as the helper.

## 3. Modules

| File | Role |
|---|---|
| `core/engine.py` | Orchestration: scan, discovery, download + verify, plan file, the elevated helper (`execute_plan`), result and live-log forwarding. |
| `core/scanner_win.py` | Joins `Win32_PnPEntity`, `Win32_PnPSignedDriver`, `Win32_SystemDriver`. Transport is pluggable: PowerShell CIM or JSON fixtures. |
| `core/scanner_linux.py` | PCI/USB inventory, microcode, kernel modules, fwupd devices. |
| `core/model.py` | `Device`, `Update`, verification checks, version comparison, `dedupe_devices` (one entry per identical device; all instance IDs kept). |
| `core/discovery/` | `windows_update.py` (Windows Update Agent COM: search, download, install fallback), `ms_catalog.py` (Microsoft Update Catalog by hardware ID), `linux_lvfs.py` (fwupd over D-Bus, else `fwupdmgr`; distro driver tools). |
| `core/verifier.py` | HTTPS-only fetches, SHA-256 gated downloads and staging copies, Authenticode (`Get-AuthenticodeSignature`, i.e. WinVerifyTrust) with publisher matching, catalog signers, GPG via `gpgv` against root-owned keyrings. |
| `core/security/loldrivers.py` | The LOLDrivers (BYOVD) list of known vulnerable drivers. |
| `core/installer.py` | Unpacking (zip, cab via `tar`, `expand.exe` as fallback; every tree checked for path traversal), `pnputil /add-driver … /install`, fwupd, apt/dnf/pacman/zypper. `dry_run=True` by default. |
| `core/restore.py` | `Checkpoint-Computer … DEVICE_DRIVER_INSTALL`, `timeshift --create`, `snapper create`; reports created / existing / unavailable / failed. |
| `core/elevation.py` | Which helper to elevate; `IsUserAnAdmin`, `ShellExecuteExW` verb `runas`, `pkexec` / `sudo`. |
| `core/manifest.py`, `core/trust.py` | Manifest schema checks, signature, expiry and rollback; pinned manifest keys (no flag or environment variable can add one). |
| `core/common.py` | Command runner (`run`, `powershell`, output decoding in the ANSI/OEM code pages), the audit log, local-time stamps. |
| `core/diagnostics.py`, `core/updates.py` | LOG drawer text for audit records; the optional startup check for a newer release. |
| `ui/` | PySide6 window: one Matrix design with accent and font presets (`theme.py`, `settings.py`, `settings_dialog.py`), table model and painted cells, dialogs, background workers. |

## 4. Verification pipeline (in order)

1. **Manifest authenticity**: a detached Ed25519 signature over the exact manifest bytes, public
   key pinned in `core/trust.py`. Detached, so no JSON canonicalisation is needed.
2. **Manifest freshness**: `expires` must be in the future (freeze attack); `sequence` must not
   be lower than the last one seen (rollback attack).
3. **Transport**: HTTPS only; redirects to non-HTTPS are refused.
4. **Size and SHA-256**: streamed while downloading; aborts as soon as the declared size is
   exceeded. On mismatch the partial file is deleted and the event is logged.
5. **Publisher signature**: Windows: Authenticode, signer subject/thumbprint must match the
   manifest; Catalog packages must carry a `.cat` signed by Microsoft's hardware publisher;
   packages the elevated helper received from the Windows Update Agent itself accept any valid
   signer (Windows Update is then the trust anchor), never an unsigned or altered one. Linux:
   `gpgv` against a pinned keyring; fwupd/LVFS and distro packages are verified by their tools.
6. **Known vulnerable drivers**: every `.sys` is checked against LOLDrivers, by the front end
   after download and again by the helper. A hit aborts the whole plan; an unreachable list
   stops the install until the user agrees.
7. **Snapshot**: System Restore point or Timeshift/snapper. If none can be created the user
   must explicitly agree.
8. **Install**: `pnputil` (with the Windows Update Agent's own installer as fallback for its
   packages), fwupd, or the package manager.

A SHA-256 published next to a file on the same server proves only that the download was not
corrupted; authenticity comes from steps 1 and 5.

## 5. Rules the code enforces

- **Dry run by default.** Only `--apply` (CLI, plus typing `install` or `--yes`) or the window's
  install button plus its confirmation dialog leads to an install.
- **Everything is verified before anything changes.** Hash, publisher signature, unpacking,
  catalog signer and the LOLDrivers check all happen before the restore point is requested.
- **No restore point, no install**, unless the user explicitly agrees or passes
  `--allow-no-snapshot`. On Linux with neither Timeshift nor snapper installed the helper logs a
  warning and continues. A package with `snapshot_required: true` is never installed without one.
- **Windows restore points:** Windows silently skips creation if one was made in the last 24
  hours; that is reported as `existing`, not as an error.
- **No vendor `.exe` installers**: their silent switches differ per vendor and they run arbitrary
  code as administrator. Windows packages are INF driver packages (`.cab` or `.zip`). On Linux,
  vendor `.run` installers are never used; the package manager is.

## 6. Audit log

Append-only JSON Lines, one record per hardware query, subprocess, network request,
verification result and install action, stamped in local time with the UTC offset. Each record
carries the hash of the previous one, so truncation or editing is detectable with
`driver-installer verify-log`. Stored locally only (`%ProgramData%\SafeDriver\logs` and
`/var/log/safedriver` for the helper, the per-user state directory otherwise).

## 7. Manifests and signing keys

`core/trust.py` ships with no key, so every manifest is refused until one is pinned
(`docs/SIGNING.md`):

```
python tools/keygen.py --out ~/safedriver-signing.key --pin
python tools/build_manifest.py --driver-dir drivers/ --url-prefix https://dl.example.org/drivers \
    --private-key ~/safedriver-signing.key --output manifest.json      # or write one by hand and:
python tools/sign_manifest.py --key ~/safedriver-signing.key manifest.json
python src/cli.py update --all --manifest manifest.json            # dry run
```

## 8. Tested, and not yet

The pytest suite runs on Linux and on a Windows runner without administrator rights or network:
manifest pinning, expiry and rollback; downloads against loopback servers; real GPG signatures;
WMI parsing from fixtures; the Windows Update and Catalog flows with stand-ins; the full dry-run /
elevate / helper flow with a fake command runner, and the helper as a real `python -I`
subprocess; the window. The release workflow also installs `DriverInstaller-Setup.exe` on a
Windows runner as a standard user, upgrades it while running, and uninstalls it; it unpacks a
real makecab `.cab` and checks the elevated helper's refusals.

Not exercised automatically: a real driver install from Windows Update on physical hardware,
System Restore, real `pkexec`, `fwupdmgr`, Timeshift, snapper or package-manager runs. Treat the
first run on real hardware as a test: use a VM or a machine you can re-image.

## 9. Known gaps and design history

- Run from a source checkout (or a portable `DriverInstaller.exe`), the helper is a file your
  own account can modify; the tool warns each time. Setup, the .deb and
  `tools/install_helper.sh` / `.ps1` install it to an administrators-only path.
- Windows builds are Authenticode-signed only when the repository has the signing secrets.
- The original design (Phase 1) proposed Rust for the core and helper, with Tauri for the GUI,
  so the elevated code would be a small static binary calling WinVerifyTrust and SetupAPI
  directly instead of parsing PowerShell output. The implementation is Python with PySide6 but
  keeps that process model; moving the helper to a compiled language remains the recommended
  step before wide distribution.
- Open questions: who signs public manifests and where the key lives (an offline key with
  threshold signing, TUF-style roles); how manifest entries are sourced and reviewed (pull
  requests with CI that re-downloads and re-hashes every artifact).
