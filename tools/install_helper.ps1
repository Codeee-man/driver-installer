#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Source checkout only: freeze the elevated helper and install it into
  %ProgramFiles%\driver-installer with an admin-only ACL.

.DESCRIPTION
  Releases do not need this script: DriverInstaller-Setup.exe installs the program to
  %ProgramFiles%\Driver Installer with the same protection.

  The helper is the only part of SafeDriver that runs elevated. Run from a
  checkout, it is a Python script in a folder your account can edit, so any
  program running as you could change what the UAC prompt elevates. This
  script freezes src\helper_main.py with PyInstaller and installs it to
  Program Files with an ACL that only Administrators and SYSTEM can write.

  The frozen helper contains its own copy of core\trust.py. Pin your manifest
  key first (py tools\keygen.py --pin), and re-run this script after any change.

  Requires: Python 3.10+ installed for all users, plus
      py -m pip install cryptography pyinstaller

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File tools\install_helper.ps1
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File tools\install_helper.ps1 -Uninstall
#>
[CmdletBinding()]
param(
    [switch]$Uninstall,
    [string]$Python = 'py'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repo = Split-Path -Parent $PSScriptRoot
$dest = Join-Path $env:ProgramFiles 'driver-installer'
$entry = Join-Path $repo 'src\helper_main.py'

if ($Uninstall) {
    if (Test-Path -LiteralPath $dest) { Remove-Item -LiteralPath $dest -Recurse -Force }
    Write-Host "Removed $dest. Audit log and state remain in $env:ProgramData\SafeDriver."
    return
}

function Set-AdminOnlyAcl([string]$path) {
    # Administrators + SYSTEM: full control. Users: read and execute only, so a normal
    # (non-elevated) user can start the helper but cannot change any file.
    & icacls $path /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not set the ACL on $path." }
}

function Reset-ChildAcls([string]$path) {
    # Every file and folder below $path inherits exactly the ACL above, nothing else.
    & icacls (Join-Path $path '*') /reset /T /C /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not reset the ACLs below $path." }
}

function Remove-DownloadMark([string]$path) {
    # Files unzipped from a download carry a Zone.Identifier stream ("mark of the web").
    # Windows can then refuse to start them, or each DLL of the bundled runtime, from
    # Program Files. Unblock-File removes that mark; it changes nothing else.
    Get-ChildItem -LiteralPath $path -Recurse -File -Force | Unblock-File
}

function Assert-UsersCanRun([string]$exe) {
    $acl = Get-Acl -LiteralPath $exe
    $sid = { param($rule) try { $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } catch { '' } }
    $rules = @($acl.Access | Where-Object { $_.AccessControlType -eq 'Allow' })
    $users = @($rules | Where-Object { (& $sid $_) -eq 'S-1-5-32-545' -and ($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::ReadAndExecute) -eq [Security.AccessControl.FileSystemRights]::ReadAndExecute })
    $admins = @($rules | Where-Object { (& $sid $_) -eq 'S-1-5-32-544' -and ($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -eq [Security.AccessControl.FileSystemRights]::FullControl })
    # Only rights that change the file count; Modify/Write as a whole also contain read bits.
    $writeBits = [Security.AccessControl.FileSystemRights]'WriteData, AppendData, WriteExtendedAttributes, WriteAttributes, Delete, ChangePermissions, TakeOwnership'
    $writers = @($rules | Where-Object { (& $sid $_) -notin 'S-1-5-32-544', 'S-1-5-18' -and ($_.FileSystemRights -band $writeBits) })
    if (-not $users) { throw "BUILTIN\Users cannot read and execute $exe." }
    if (-not $admins) { throw "BUILTIN\Administrators do not have full control of $exe." }
    if ($writers) { throw "Someone other than Administrators/SYSTEM can modify ${exe}: $($writers.IdentityReference -join ', ')" }
    if (Get-Item -LiteralPath $exe -Stream Zone.Identifier -ErrorAction SilentlyContinue) { throw "$exe still carries a download mark." }
}

# ---- Source checkout: build the helper with PyInstaller.

if (-not (Test-Path -LiteralPath $entry)) { throw "Run this from a driver-installer checkout ($entry not found)." }

function Invoke-Python {
    & $Python @args
    if ($LASTEXITCODE -ne 0) { throw "python $($args -join ' ') failed with exit code $LASTEXITCODE" }
}

Invoke-Python -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)'
try { Invoke-Python -c 'import cryptography, PyInstaller' }
catch { throw "Missing build dependencies. Run: $Python -m pip install cryptography pyinstaller" }

& $Python -c "import sys; sys.path.insert(0, sys.argv[1]); from core import trust; sys.exit(0 if trust.PINNED_MANIFEST_KEYS else 1)" (Join-Path $repo 'src')
if ($LASTEXITCODE -ne 0) {
    Write-Warning 'No manifest signing key is pinned in src\core\trust.py. The installed helper will refuse every manifest. Run "py tools\keygen.py --pin" and re-run this script.'
}

# Build in a directory only this (elevated) session can write, never inside the checkout.
$build = Join-Path ([IO.Path]::GetTempPath()) ('sd-build-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $build | Out-Null
try {
    & icacls $build /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not lock down the build directory.' }

    # --onedir: nothing is unpacked to a temp folder when the elevated helper starts.
    Invoke-Python -m PyInstaller --noconfirm --clean --onedir --noconsole --name helper `
        --paths (Join-Path $repo 'src') --distpath (Join-Path $build 'dist') `
        --workpath (Join-Path $build 'work') --specpath $build $entry

    if (Test-Path -LiteralPath $dest) { Remove-Item -LiteralPath $dest -Recurse -Force }
    New-Item -ItemType Directory -Path $dest | Out-Null
    Set-AdminOnlyAcl $dest
    Copy-Item -Path (Join-Path $build 'dist\helper\*') -Destination $dest -Recurse -Force
    Remove-DownloadMark $dest
    Reset-ChildAcls $dest
}
finally {
    Remove-Item -LiteralPath $build -Recurse -Force -ErrorAction SilentlyContinue
}

$helper = Join-Path $dest 'helper.exe'
if (-not (Test-Path -LiteralPath $helper)) { throw "Build finished but $helper is missing." }
Assert-UsersCanRun $helper
$hash = (Get-FileHash -LiteralPath $helper -Algorithm SHA256).Hash
Write-Host "Installed $helper"
Write-Host "SHA-256   $hash"
Write-Host 'The helper is not code-signed, so the UAC prompt will show "Unknown publisher" until you sign it (tools\codesign_windows.py, see docs\SIGNING.md).'
