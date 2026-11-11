#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Install Driver Installer into %ProgramFiles%\driver-installer with an admin-only ACL.

.DESCRIPTION
  Two modes, chosen automatically:

  Release folder (unzipped driver-installer-windows.zip, this script sits next to
  driver-installer-helper.exe): copies the whole prebuilt folder to Program Files and
  adds a Start menu shortcut. Nothing is built; no Python is needed.

  Source checkout (tools\install_helper.ps1): builds the helper as described below.

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
  powershell -ExecutionPolicy Bypass -File .\install_helper.ps1      # from the unzipped release
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

$shortcut = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Driver Installer.lnk'

if ($Uninstall) {
    if (Test-Path -LiteralPath $dest) { Remove-Item -LiteralPath $dest -Recurse -Force }
    if (Test-Path -LiteralPath $shortcut) { Remove-Item -LiteralPath $shortcut -Force }
    Write-Host "Removed $dest. Audit log and state remain in $env:ProgramData\SafeDriver."
    return
}

function Set-AdminOnlyAcl([string]$path) {
    # Administrators + SYSTEM: full control. Users: read and execute only.
    & icacls $path /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not set the ACL on $path." }
}

# ---- Release folder: install the prebuilt program as it is.
$prebuilt = Join-Path $PSScriptRoot 'driver-installer-helper.exe'
if (Test-Path -LiteralPath $prebuilt) {
    $here = (Resolve-Path -LiteralPath $PSScriptRoot).Path.TrimEnd('\')
    if ($here -ieq $dest.TrimEnd('\')) { throw "Already installed in $dest; run this from the unzipped download instead." }
    if (Test-Path -LiteralPath $dest) { Remove-Item -LiteralPath $dest -Recurse -Force }
    New-Item -ItemType Directory -Path $dest | Out-Null
    Set-AdminOnlyAcl $dest
    Copy-Item -Path (Join-Path $PSScriptRoot '*') -Destination $dest -Recurse -Force
    foreach ($exe in 'driver-installer.exe', 'driver-installer-gui.exe', 'driver-installer-helper.exe') {
        if (-not (Test-Path -LiteralPath (Join-Path $dest $exe))) { throw "$exe is missing from the release folder." }
    }
    $shell = New-Object -ComObject WScript.Shell
    $link = $shell.CreateShortcut($shortcut)
    $link.TargetPath = Join-Path $dest 'driver-installer-gui.exe'
    $link.WorkingDirectory = $dest
    $link.Description = 'Driver Installer'
    $link.Save()
    $hash = (Get-FileHash -LiteralPath (Join-Path $dest 'driver-installer-helper.exe') -Algorithm SHA256).Hash
    Write-Host "Installed to $dest (Start menu: Driver Installer)."
    Write-Host "Helper SHA-256 $hash (compare with BUILD-INFO.txt)."
    Write-Host 'The executables are not code-signed, so UAC shows "Unknown publisher".'
    return
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
    # Administrators + SYSTEM: full control. Users: read and execute only.
    & icacls $dest /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not set the ACL on $dest." }
    Copy-Item -Path (Join-Path $build 'dist\helper\*') -Destination $dest -Recurse -Force
}
finally {
    Remove-Item -LiteralPath $build -Recurse -Force -ErrorAction SilentlyContinue
}

$helper = Join-Path $dest 'helper.exe'
if (-not (Test-Path -LiteralPath $helper)) { throw "Build finished but $helper is missing." }
$hash = (Get-FileHash -LiteralPath $helper -Algorithm SHA256).Hash
Write-Host "Installed $helper"
Write-Host "SHA-256   $hash"
Write-Host 'The helper is not code-signed, so the UAC prompt will show "Unknown publisher" until you sign it (signtool).'
