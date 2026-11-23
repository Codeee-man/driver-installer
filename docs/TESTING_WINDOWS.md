# Testing on Windows

Every release tag runs the whole suite on a Windows runner, builds `DriverInstaller.exe` and
`DriverInstaller-Setup.exe`, installs them and starts them as a standard user (see
`.github/workflows/build.yml`). Catalog discovery was also checked live there. What a runner
cannot show is a real PC: its own drivers, Windows Update offers (blocked by policy on the
runner) and real installs. For that, use a throwaway environment; never a machine you need.

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
   py -m pytest -q        # a few POSIX-only tests are skipped on Windows
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

Then pin a key, sign, and install the helper (see [SIGNING.md](SIGNING.md)).

## 4. Run and check

```powershell
py src\cli.py check --manifest m.json; $LASTEXITCODE            # expect 1
py src\cli.py update --all --manifest m.json                    # dry run: nothing changes
py src\cli.py update --all --manifest m.json --apply            # type 'install', accept UAC
py src\cli.py verify-log
```

| Check | Expected |
|---|---|
| UAC prompt | Appears once, for `DriverInstaller.exe` in Program Files (installed with Setup), `helper.exe` (installed from a checkout), or the portable/`python.exe` copy plus a warning |
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

## 4b. Discovery, and finding out why it found nothing

Discovery was verified live on a Windows runner (catalog search, details, download, digest,
LOLDrivers, Microsoft signature). On a real PC, run:

```powershell
driver-installer check --debug                    # installed with the PATH option: every step, to the console
start /wait .\DriverInstaller.exe check --debug   # portable folder, from cmd.exe
```
or open the window and press LOG. The trace shows, in order:

| Line | What it tells you |
|---|---|
| `scan.windows.done` | WMI devices found. 0 here means the WMI query failed (see the line before it) |
| `wua.done` | What Windows Update offers this PC, and why each offer was not used. A `note: policy ...` line means your update policy hides drivers (WSUS, `ExcludeWUDriversInQualityUpdate`) |
| `catalog.start` | How many devices have a PCI/USB hardware ID to search for |
| `catalog.device` | Per device: each hardware ID searched (full, then base), how many results, and the reason each was skipped: older than installed, wrong Windows release, wrong architecture, hardware ID not supported |
| `discovery.windows` | How many updates each source found |
| `catalog.redirect` | The catalog answered the download dialog with a redirect; `-> ErrorInline.aspx` means it has no public copy of that update (common for OEM drivers Windows Update offers) |
| `wua.fetch.done` / `wua.fetch.failed` | The Windows Update Agent handed over the driver's .cab, or why not (HRESULT and meaning, e.g. only administrators may download it) |
| `verify.channel_trust` | The driver comes through Windows Update and only an administrator may download it: its checks are "checked by the installer", which downloads it through Windows Update and runs every check before installing |
| `verify.failed` | Verification is None: which step failed and the real reason. The same reasons are in the (?) next to the badge |

"Not newer than the installed driver" for every device is a normal result on a PC that
Windows Update keeps current. Send the `--debug` output if the reasons look wrong.

## 4c. "Windows cannot access the specified device, path, or file"

Download [`tools/diagnose_windows.ps1`](../tools/diagnose_windows.ps1) from the repository (it is no longer inside the zip) and run
it, normal user first, then as Administrator:

```powershell
powershell -ExecutionPolicy Bypass -File .\diagnose_windows.ps1 -Path "$env:USERPROFILE\Downloads\DriverInstaller"
powershell -ExecutionPolicy Bypass -File .\diagnose_windows.ps1        # the installed copy in Program Files
```
It checks, without changing anything: starting from inside the .zip, missing files,
Defender detections, Smart App Control, the code signature, the download mark
(Zone.Identifier), folder permissions, AppLocker/App Control, and whether `DriverInstaller.exe`
starts. `DriverInstaller-Setup.exe` installs without a download mark and with Users set to
Read & Execute; the build workflow installs it and checks that a standard user can run the
CLI and the GUI but cannot write into the folder.

## 5. A real upgrade

Only after section 4 passes: revert to `clean`, download a genuinely newer INF
driver package from the hardware vendor, repeat section 3 with it, install, and
reboot if asked. Roll back with **rstrui.exe** to confirm the restore point works.

## Report back

Which rows of the table failed, the last 30 lines of both audit logs, and the
`pytest` failures from step 1.3.
