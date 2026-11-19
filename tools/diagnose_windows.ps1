<#
.SYNOPSIS
  Find out why Windows refuses to start Driver Installer.

.DESCRIPTION
  Checks each known cause of "Windows cannot access the specified device, path, or file.
  You may not have the appropriate permissions to access the item." and of other start-up
  failures, and prints what it finds. It changes nothing on the computer.

    1. Started from inside the .zip (Explorer's "compressed folder" view) instead of an unzipped folder
    2. Files missing, e.g. removed by an antivirus after unzipping
    3. Microsoft Defender detections or quarantined files for this folder
    4. Smart App Control (Windows 11) blocking unsigned programs
    5. "Mark of the web" (Zone.Identifier) left on the unzipped files
    6. Folder permissions (ACL): Users need Read & Execute
    7. AppLocker / Windows Defender Application Control policies
    8. Whether driver-installer.exe actually starts

  Run it as your normal user first; run it again as Administrator to also see Defender history.

.PARAMETER Path
  Folder that contains driver-installer-gui.exe. Default: the folder of this script, else
  %ProgramFiles%\driver-installer.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\diagnose_windows.ps1
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\diagnose_windows.ps1 -Path "$env:ProgramFiles\driver-installer"
#>
[CmdletBinding()]
param([string]$Path)
$ErrorActionPreference = 'Continue'
Set-StrictMode -Version Latest

$exes = 'driver-installer.exe', 'driver-installer-gui.exe', 'driver-installer-helper.exe'
if (-not $Path) {
    $Path = if (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'driver-installer-gui.exe')) { $PSScriptRoot }
            else { Join-Path $env:ProgramFiles 'driver-installer' }
}
$findings = New-Object System.Collections.Generic.List[string]
function Say([string]$label, [string]$text) { Write-Host ('{0,-22} {1}' -f $label, $text) }
function Problem([string]$text) { $findings.Add($text); Write-Host "  !! $text" -ForegroundColor Yellow }

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Say 'Folder' $Path
Say 'Running as' ("{0}{1}" -f [Security.Principal.WindowsIdentity]::GetCurrent().Name, $(if ($isAdmin) { ' (Administrator)' } else { '' }))
Say 'Windows' ([Environment]::OSVersion.VersionString)

# 1. inside a zip
if ($Path -match '\\Temp\d*_[^\\]+\.zip' -or $Path -match '\.zip(\\|$)') {
    Problem 'This looks like the inside of a .zip. Right-click the .zip > Extract All, then start the program from the extracted folder.'
}

# 2. files present
foreach ($exe in $exes) {
    $file = Join-Path $Path $exe
    if (Test-Path -LiteralPath $file) { Say $exe ('present, {0:N0} bytes' -f (Get-Item -LiteralPath $file).Length) }
    else { Problem "$exe is missing. If it was there after unzipping, an antivirus probably removed it (see below)." }
}
if (-not (Test-Path -LiteralPath (Join-Path $Path '_internal'))) { Problem "The _internal folder is missing: unzip the whole archive, not single files." }

# 3. Defender
try {
    $mp = Get-MpComputerStatus -ErrorAction Stop
    Say 'Defender' ("real-time protection {0}, signatures {1}" -f $mp.RealTimeProtectionEnabled, $mp.AntivirusSignatureVersion)
    $hits = @(Get-MpThreatDetection -ErrorAction Stop | Where-Object { @($_.Resources) -match [regex]::Escape('driver-installer') })
    foreach ($h in $hits) {
        $threat = @(Get-MpThreat -ThreatID $h.ThreatID -ErrorAction SilentlyContinue) | Select-Object -First 1
        $name = if ($threat) { $threat.ThreatName } else { "threat $($h.ThreatID)" }
        Problem ("Defender detected {0} in {1} on {2} (action {3}). Probably a false positive for an unsigned PyInstaller program: restore it under Windows Security > Protection history, and report it at https://www.microsoft.com/wdsi/filesubmission" -f $name, (@($h.Resources) -join ', '), $h.InitialDetectionTime, $h.ThreatStatusID)
    }
    if (-not $hits) { Say '' 'no Defender detections for driver-installer' }
} catch {
    Say 'Defender' $(if ($isAdmin) { "not readable: $($_.Exception.Message)" } else { 'history needs Administrator; run this script again elevated' })
}

# 4. Smart App Control
$ci = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' -ErrorAction SilentlyContinue
$sac = if ($ci -and $ci.PSObject.Properties['VerifiedAndReputablePolicyState']) { [int]$ci.VerifiedAndReputablePolicyState } else { $null }
$sacText = switch ($sac) { 0 { 'off' } 1 { 'ON' } 2 { 'evaluation mode' } $null { 'not present (Windows Server or older Windows 11)' } default { "unknown state $sac" } }
Say 'Smart App Control' $sacText
$guiExe = Join-Path $Path 'driver-installer-gui.exe'
$sig = if (Test-Path -LiteralPath $guiExe) { Get-AuthenticodeSignature -LiteralPath $guiExe } else { $null }
$sigText = if (-not $sig) { 'n/a' } elseif ($sig.Status -eq 'Valid') { "Valid, $($sig.SignerCertificate.Subject)" } else { [string]$sig.Status }
Say 'Code signature' $sigText
if ($sig -and $sig.Status -notin 'Valid', 'NotSigned') {
    Problem "The signature of driver-installer-gui.exe is $($sig.Status): $($sig.StatusMessage) If the release uses a self-signed certificate, trust its .cer (SIGNING.md); otherwise the file was changed after signing: download it again."
}
if ($sac -eq 1 -and (-not $sig -or $sig.Status -ne 'Valid')) { Problem 'Smart App Control is on. It blocks programs without a valid code signature from a trusted certificate authority, which this copy of Driver Installer lacks. Windows Security > App & browser control > Smart App Control.' }

# 5. mark of the web
$marked = @(Get-ChildItem -LiteralPath $Path -Recurse -File -ErrorAction SilentlyContinue | Where-Object { Get-Item -LiteralPath $_.FullName -Stream Zone.Identifier -ErrorAction SilentlyContinue })
Say 'Download mark' ("{0} file(s) still carry Zone.Identifier" -f $marked.Count)
if ($marked.Count) { Problem 'Files still carry the download mark. Run install_helper.ps1 as Administrator (it removes it), or: Get-ChildItem -Recurse | Unblock-File' }

# 6. permissions
foreach ($exe in $exes) {
    $file = Join-Path $Path $exe
    if (-not (Test-Path -LiteralPath $file)) { continue }
    $text = (& icacls $file 2>&1 | Select-Object -Skip 0) -join ' '
    try { [IO.File]::OpenRead($file).Close(); $readable = $true } catch { $readable = $false }
    Say "ACL $exe" $(if ($readable) { 'readable by you' } else { 'NOT readable by you' })
    if (-not $readable) { Problem "You cannot read $exe. Run install_helper.ps1 as Administrator to reset the permissions (Users: Read & Execute)." }
    if ($text -notmatch 'BUILTIN\\Users:(\(I\))?\((RX|F|M)\)') {
        Problem "BUILTIN\Users has no Read & Execute entry on $exe. ACL: $text"
    }
}

# 7. application control policies
try {
    $applocker = Get-AppLockerPolicy -Effective -ErrorAction Stop
    $rules = @($applocker.RuleCollections | ForEach-Object { $_ } | Where-Object { $_ })
    Say 'AppLocker' ("{0} effective rule(s)" -f $rules.Count)
    if ($rules.Count) { Problem 'AppLocker rules are in effect; ask your administrator whether unsigned programs outside Program Files are allowed.' }
} catch { Say 'AppLocker' 'not configured' }
$wdac = Get-ChildItem 'C:\Windows\System32\CodeIntegrity\CiPolicies\Active' -ErrorAction SilentlyContinue
Say 'App Control (WDAC)' ("{0} active policy file(s)" -f @($wdac).Count)

# 8. try it
$cli = Join-Path $Path 'driver-installer.exe'
if (Test-Path -LiteralPath $cli) {
    try {
        $p = Start-Process -FilePath $cli -ArgumentList '--version' -NoNewWindow -Wait -PassThru -RedirectStandardOutput "$env:TEMP\di-version.txt" -ErrorAction Stop
        Say 'Start test' ("driver-installer.exe --version exited {0}: {1}" -f $p.ExitCode, ((Get-Content "$env:TEMP\di-version.txt" -ErrorAction SilentlyContinue) -join ' '))
        if ($p.ExitCode -ne 0) { Problem "driver-installer.exe started but exited with $($p.ExitCode)." }
    } catch {
        Problem ("Windows refused to start driver-installer.exe: {0} (0x{1:X8})" -f $_.Exception.Message, $_.Exception.HResult)
    }
}

Write-Host ''
if ($findings.Count) {
    Write-Host 'Likely causes, most important first:' -ForegroundColor Yellow
    $findings | ForEach-Object { Write-Host " - $_" }
} else {
    Write-Host 'No problem found. If the GUI still does not start, send this output and the "Start test" line.'
}
