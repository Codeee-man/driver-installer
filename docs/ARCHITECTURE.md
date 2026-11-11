# SafeDriver (`driver-installer`) — Architecture, Phase 1

A driver and firmware updater with no ads, no telemetry, no bundled extras and
no process left running after exit.

## 1. Design principles

1. **Index, don't host.** SafeDriver never repackages or mirrors drivers. The
   manifest is a signed *index* that points at the vendor's or distro's own
   download and records the expected SHA-256 and signer. This is the main
   difference from Driver Booster-style tools, whose private driver databases
   are the root of both their trust problem and their bad-driver problem.
2. **Prefer the platform's own channel.** Windows Update / Microsoft Update
   Catalog (WHQL-signed) and OEM feeds on Windows; LVFS via `fwupd` and the
   distro package manager on Linux. The manifest covers what those miss.
3. **Fail closed.** Unsigned or expired manifest, hash mismatch, bad
   Authenticode/GPG signature, missing snapshot: the update does not proceed.
4. **Least privilege, short-lived.** The GUI and scanner run unprivileged. A
   small helper is elevated (UAC / polkit) only for the apply step and exits
   when it finishes. No service, no scheduled task, no tray icon, no autostart.
5. **Everything is logged locally, nothing is sent anywhere.** The only
   network requests are manifest fetches and package downloads, each logged.

## 2. Tech stack comparison

| | Python + PySide6 | Rust + Tauri |
|---|---|---|
| Iteration speed | Fast; ideal for PoC | Slower builds, stricter compiler |
| Windows APIs (SetupAPI, CfgMgr32, WinVerifyTrust, SRSetRestorePoint) | Via PowerShell subprocesses or `ctypes`/`pywin32` | Direct, typed, via `windows-rs` |
| Linux APIs (fwupd D-Bus, sysfs, polkit) | `dbus-next` / `pydbus` | `zbus`, native |
| Memory safety in elevated code | Safe language, but large runtime + C extensions run elevated | Safe, small audited surface |
| Distribution | Bundled interpreter (PyInstaller/Nuitka), 60–120 MB, frequent AV false positives | Single binary, ~5–15 MB; uses system WebView2 / WebKitGTK |
| Supply chain | PyPI wheels incl. Qt binaries | Cargo crates (`cargo-vet`, `cargo-deny`), reproducible builds feasible |
| GUI | Native Qt widgets, mature | Web UI in system webview; strict CSP needed |
| Licensing | PySide6 is LGPL | MIT/Apache |

**Recommendation:** Python + PySide6 for the PoC (this phase); **Rust for the
core, CLI and privileged helper** in production, with Tauri as the GUI. The
decisive points are that the elevated code path should be a small static
binary rather than an interpreter plus Qt, and that calling WinVerifyTrust and
SetupAPI directly is more reliable than parsing PowerShell output. If a
webview is unwanted, Slint or egui are drop-in alternatives because the GUI
only talks to the core through the CLI's JSON interface.

## 3. Repository layout

```
driver-installer/
├── Cargo.toml                    # workspace
├── crates/
│   ├── sd-core/                  # platform-neutral engine (library)
│   │   └── src/
│   │       ├── manifest.rs       # parse, schema checks, Ed25519 verify, expiry, anti-rollback
│   │       ├── fetch.rs          # HTTPS-only streaming download + SHA-256 gate
│   │       ├── verify.rs         # hash + signer policy
│   │       ├── plan.rs           # match devices to packages, version compare
│   │       ├── audit.rs          # hash-chained JSONL log
│   │       └── model.rs          # Device, Package, Update, events
│   ├── sd-platform/              # trait Platform { scan, verify_sig, snapshot, install }
│   │   └── src/
│   │       ├── windows/          # pnp.rs, authenticode.rs, restore_point.rs, pnputil.rs
│   │       └── linux/            # pci.rs, usb.rs, microcode.rs, fwupd.rs, dkms.rs,
│   │                             # gpg.rs, snapshot.rs (timeshift/snapper), pkgmgr.rs
│   ├── sd-cli/                   # `safedriver --scan | --dry-run | --update-all [--json]`
│   └── sd-helper/                # elevated one-shot: takes a verified plan, applies, exits
├── gui/
│   ├── src-tauri/                # thin shell; spawns sd-cli, relays JSON events
│   └── ui/                       # Scan → Review → Apply (dark theme, no remote content)
├── schema/
│   ├── manifest.schema.json
│   └── example.manifest.json
├── poc/
│   └── safedriver_poc.py         # Phase 1 proof of concept
├── packaging/
│   ├── windows/                  # WiX/MSI, signing config
│   └── linux/                    # deb, rpm, polkit policy, .desktop
├── tests/                        # fixtures: lspci dumps, WMI JSON, tampered packages
├── docs/                         # ARCHITECTURE.md, THREAT_MODEL.md, MANIFEST.md
└── .github/workflows/            # build, test, cargo-deny, reproducibility check
```

## 4. Process model

```
 GUI (unprivileged) ──spawns──▶ sd-cli (unprivileged)
                                  │ scan, fetch manifest, plan,
                                  │ download + verify into quarantine dir
                                  ▼
                        sd-helper (elevated via UAC / pkexec, one-shot)
                                  │ re-verifies SHA-256 of each file,
                                  │ snapshot → install → report → exit
```

- The helper re-hashes every file itself against the signed manifest, so a
  compromised GUI or a file swapped between download and install (TOCTOU)
  cannot get an unverified package installed.
- The quarantine directory is owner-only; files are written without execute
  permission and are named by their hash only after verification.
- The GUI exits its worker threads and child processes on close.

## 5. Verification pipeline (mandatory, in order)

1. **Manifest authenticity** — detached Ed25519 signature over the exact
   manifest bytes, public key pinned in the binary. Detached, so no JSON
   canonicalisation is needed.
2. **Manifest freshness** — `expires` must be in the future (freeze attack);
   `sequence` must not be lower than the last one seen (rollback attack).
3. **Transport** — HTTPS only; redirects to non-HTTPS are refused.
4. **Size and SHA-256** — streamed while downloading; aborts as soon as the
   declared size is exceeded; constant-time digest comparison. On mismatch the
   partial file is deleted, the event is logged and the user is alerted.
5. **Publisher signature** — Windows: Authenticode via WinVerifyTrust, signer
   thumbprint/subject must match the manifest. Linux: `gpgv` against a pinned
   keyring; fwupd/LVFS and distro packages are verified by their own tooling.
6. **Snapshot** — System Restore point (Windows) or Timeshift/snapper (Linux).
   If none can be created the user must explicitly confirm.
7. **Install** — `pnputil /add-driver … /install`, `fwupd` D-Bus `Install`,
   or the native package manager.

A SHA-256 published next to the file on the same server proves only that the
download was not corrupted. Authenticity comes from steps 1 and 5.

## 6. Platform notes

**Windows:** enumerate with CfgMgr32/SetupAPI (PoC: `Win32_PnPEntity` joined
to `Win32_PnPSignedDriver` on `PNPDeviceID`); compare `DriverVersion` to the
manifest; restore points via `SRSetRestorePoint` (Windows rate-limits these to
one per 24 h by default, so "already created today" counts as success).

**Linux:** PCI/USB from sysfs with `lspci`/`lsusb`/`lshw` for names; microcode
revision from `/proc/cpuinfo`; fwupd over D-Bus (`org.freedesktop.fwupd`:
`GetDevices`, `GetUpgrades`, `Install`) for UEFI, NVMe and system firmware;
NVIDIA and other out-of-tree modules via `/sys/module/*/version`, `dkms
status` and the distro's driver tooling (`ubuntu-drivers`, `dnf`, `pacman`).
SafeDriver never runs vendor `.run` installers on Linux; it delegates to the
package manager.

## 7. Audit log

Append-only JSON Lines, one record per hardware query, subprocess, network
request, verification result and install action. Each record carries the hash
of the previous one, so truncation or editing is detectable with
`safedriver --verify-log`. Stored locally only
(`%ProgramData%\SafeDriver\logs`, `/var/log/safedriver` for the helper;
per-user state dir for the unprivileged side).

## 8. PoC scope and limits

`poc/safedriver_poc.py` implements scanning on both OSes, signed-manifest
loading, the verified downloader, Authenticode/GPG check functions, the audit
log and a PySide6 window. It deliberately **does not install anything**: the
apply step prints the snapshot and install commands it would run. The fwupd
integration shells out to `fwupdmgr --json` instead of using D-Bus.

## 9. Open decisions for Phase 2

- Who signs the manifest, and where the key lives (offline key + threshold
  signing, TUF-style roles, is the natural next step).
- How manifest entries are sourced and reviewed (PRs against a public repo
  with CI that re-downloads and re-hashes every artifact).
- Whether Windows coverage should start with the Windows Update Agent API
  only, adding OEM entries later.
