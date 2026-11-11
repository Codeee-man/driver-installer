# Testing on Windows

None of the Windows code has run on real Windows yet. Use a throwaway
environment; never a machine you need.

| Environment | Good for | Not for |
|---|---|---|
| **Windows Sandbox** | `scan`, `check`, dry runs, hash and Authenticode checks. Resets on close. | Restore points (System Restore is absent), anything needing a reboot |
| **VM with a checkpoint** (Hyper-V, VirtualBox, VMware) | Everything, including real installs and restore points | - |

## 1. Prepare the VM

1. Windows 10/11 VM. Take a checkpoint named `clean`.
2. Install Python 3.12 **for all users** (so it lives in `C:\Program Files`).
3. In an ordinary (non-admin) PowerShell, from the checkout:
   ```powershell
   py -m pip install cryptography PySide6 pytest pyinstaller
   py -m pytest -q        # some tests assume POSIX file modes and may fail on Windows; note which
   ```
4. In an **elevated** PowerShell, turn System Restore on and lift the one-per-24h limit:
   ```powershell
   Enable-ComputerRestore -Drive 'C:\'
   New-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore' `
     -Name SystemRestorePointCreationFrequency -Value 0 -PropertyType DWord -Force
   ```

## 2. Scan

```powershell
py src\cli.py scan
py src\cli.py scan --json > scan.json
```
Compare a few rows with Device Manager (Driver tab: version and date). To send
back data for the test fixtures, dump the three WMI classes:
```powershell
mkdir wmi
foreach ($c in 'Win32_PnPEntity','Win32_PnPSignedDriver','Win32_SystemDriver') {
  Get-CimInstance $c | ConvertTo-Json -Depth 3 | Set-Content "wmi\$c.json" -Encoding utf8
}
py src\cli.py scan --wmi-fixture wmi     # must match the live scan
```

## 3. Build a safe test package from a driver already on the VM

Re-installing a driver the VM already has exercises the whole pipeline without
changing the system (`pnputil` answers "already up to date").

```powershell
pnputil /enum-drivers                              # pick a third-party oemNN.inf
mkdir C:\t\drv; pnputil /export-driver oem12.inf C:\t\drv
Compress-Archive C:\t\drv\* C:\t\test-driver.zip
(Get-FileHash C:\t\test-driver.zip -Algorithm SHA256).Hash.ToLower()
(Get-Item C:\t\test-driver.zip).Length
Get-AuthenticodeSignature C:\t\drv\*.cat | ForEach-Object { $_.SignerCertificate.Subject }
```
Write a manifest entry (copy the Windows package in `schema\example.manifest.json`):

- `hardware_ids`: the `ID` column of that device in `scan` (for example `pci:8086:2725`)
- `version`: higher than the installed one, or the update is not offered
- `artifact`: `format: "zip"`, the size and SHA-256 from above, `url` on any HTTPS host you control
- `signature`: `{"type": "authenticode", "target": "catalog", "subject": "<one RDN from the Subject, e.g. CN=Microsoft Windows Hardware Compatibility Publisher>"}`
- `install`: `{"method": "pnputil", "inf_path": "<name>.inf", "reboot_required": false}`
- `generated` now, `expires` a week ahead

Then pin a key, sign, and install the helper (see `docs\SIGNING.md`).

## 4. Run and check

```powershell
py src\cli.py check --manifest m.json; $LASTEXITCODE            # expect 1
py src\cli.py update --all --manifest m.json                    # dry run: nothing changes
py src\cli.py update --all --manifest m.json --apply            # type 'install', accept UAC
py src\cli.py verify-log
```

| Check | Expected |
|---|---|
| UAC prompt | Appears once, for `helper.exe` in Program Files (or `python.exe` plus a warning if the helper is not installed) |
| Restore point | `Get-ComputerRestorePoint` shows "Pre-Driver-Installer Update" |
| Result | `installed`, or `no-op ... already up to date` for the re-install test |
| `pnputil /enum-drivers` | Driver package present |
| Decline UAC | Exit code 5, "Nothing was installed" |
| Flip one byte in the zip on the server | `SHA-256 MISMATCH`, file purged, exit code 1 |
| Wrong `subject` in the manifest (re-sign) | Refused before any restore point; `pnputil` never runs |
| `Disable-ComputerRestore -Drive 'C:\'` | Prompt "Continue WITHOUT a restore point?"; answering `n` installs nothing, exit code 4 |
| Edit `m.json` without re-signing | `REFUSED: manifest signature is invalid`, exit code 2 |
| After closing | No `python`/`helper` process left in Task Manager |

GUI: `py src\cli.py gui --manifest m.json` and repeat the install and the
decline cases. The helper's own log is `C:\ProgramData\SafeDriver\audit.jsonl`.

## 4b. Discovery and the LOLDrivers check (never run against the live sites yet)

```powershell
py src\cli.py scan                      # no --manifest: searches the Microsoft Update Catalog per device
py src\cli.py update --all              # dry run: downloads the .cab files and checks them
py src\cli.py verify-log
```
| Check | Expected |
|---|---|
| `scan` | Rows marked `UPDATE` with source "Microsoft Update Catalog"; compare one against the catalog website |
| No results at all | Run with a known-outdated device; if still empty, the page layout may have changed: send the audit log |
| Download | From `*.download.windowsupdate.com` over https; "catalog digest OK" in the status |
| Install | Catalog (.cat) accepted as signed by "Microsoft Windows Hardware Compatibility Publisher" |
| Disconnect the network before `--apply` | "LOLDrivers blocklist could not be loaded", prompt, nothing installed on `n` (exit 7) |
| Known-vulnerable driver | Put a driver listed on loldrivers.io into a test zip (section 3): `SECURITY ALERT`, exit 6, file deleted |

## 5. A real upgrade

Only after section 4 passes: revert to `clean`, download a genuinely newer INF
driver package from the hardware vendor, repeat section 3 with it, install, and
reboot if asked. Roll back with **rstrui.exe** to confirm the restore point works.

## Report back

Which rows of the table failed, the last 30 lines of both audit logs, and the
`pytest` failures from step 1.3.
