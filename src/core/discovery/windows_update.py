"""Windows driver discovery through the Windows Update Agent (WUA) COM API.

This asks Windows itself which driver updates it offers for this PC, the same list Settings ›
Windows Update › Optional updates › Driver updates shows:

    Microsoft.Update.Session -> CreateUpdateSearcher().Search("IsInstalled=0 and Type='Driver' and IsHidden=0")

It runs through Windows PowerShell 5.1 (no pywin32 needed) as the ordinary user; searching
needs no administrator rights. The search honours the machine's update policy (WSUS, "exclude
drivers from quality updates"), and that policy is recorded with the results, because it is the
most common reason for an empty list.

Trust: what WUA reports is only a pointer. Each update is fetched as its .cab and goes
through the same checks as catalog drivers: digest, LOLDrivers, and a .cat signed by
Microsoft's hardware publisher (enforced again by the elevated helper). Where the .cab comes
from, in order:

  1. the Microsoft Update Catalog (same update IDs; its download dialog also gives a digest)
  2. the download URL WUA reported, if any
  3. the Windows Update Agent itself (fetch_package): IUpdateDownloader, then
     IUpdate2.CopyFromCache. Many OEM drivers exist only here: the public catalog answers
     302 -> ErrorInline.aspx for them. WUA checks every file against Microsoft-signed update
     metadata while downloading. Windows may refuse this to a standard user
     (WU_E_PER_MACHINE_UPDATE_ACCESS_DENIED); then the elevated helper does it before installing.

The COM search was verified on a real Windows runner (it returned no drivers there: a virtual
machine with Windows Update blocked by policy); results on physical hardware are untested.
"""
from __future__ import annotations

import re
from pathlib import Path

from .. import common, trust
from ..model import Device, is_newer, normalise_windows_id

SEARCH_CRITERIA = "IsInstalled=0 and Type='Driver' and IsHidden=0"
TIMEOUT = 600                      # a first search on a cold machine can take minutes

_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$out = [ordered]@{ policy = $null; updates = @(); error = $null; resultCode = $null }
$p = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -ErrorAction SilentlyContinue
if ($p) { $out.policy = [ordered]@{ ExcludeWUDriversInQualityUpdate = $p.ExcludeWUDriversInQualityUpdate
                                    WUServer = $p.WUServer
                                    DoNotConnectToWindowsUpdateInternetLocations = $p.DoNotConnectToWindowsUpdateInternetLocations } }
try {
  $session = New-Object -ComObject Microsoft.Update.Session
  $session.ClientApplicationID = 'driver-installer'
  $searcher = $session.CreateUpdateSearcher()
  $result = $searcher.Search($env:SD_CRITERIA)
  $out.resultCode = $result.ResultCode
  $out.updates = @($result.Updates | ForEach-Object {
    $u = $_
    $urls = @($u.DownloadContents | ForEach-Object { $_.DownloadUrl }) + @($u.BundledUpdates | ForEach-Object { $_.DownloadContents | ForEach-Object { $_.DownloadUrl } })
    [ordered]@{ UpdateID = $u.Identity.UpdateID; Title = $u.Title; DriverHardwareID = $u.DriverHardwareID
      DriverClass = $u.DriverClass; DriverProvider = $u.DriverProvider; DriverManufacturer = $u.DriverManufacturer
      DriverModel = $u.DriverModel; DriverVerDate = $(if ($u.DriverVerDate) { $u.DriverVerDate.ToString('yyyy-MM-dd') })
      MaxDownloadSize = [int64]$u.MaxDownloadSize; Urls = @($urls | Where-Object { $_ }) } })
} catch {
  $out.error = "$($_.Exception.Message) (0x{0:X8})" -f $_.Exception.HResult
}
$out | ConvertTo-Json -Depth 6 -Compress
"""

_VERSION = re.compile(r"(\d+(?:\.\d+){1,3})(?=\)?\s*$)")
_GUID = re.compile(r"^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$")
RESULT_CODES = {0: "not started", 1: "in progress", 2: "succeeded", 3: "succeeded with errors", 4: "failed", 5: "aborted"}


class WindowsUpdateError(Exception):
    """The Windows Update Agent could not be queried, or would not hand over an update."""

    def __init__(self, message: str, hresult: str = "", stage: str = ""):
        super().__init__(message)
        self.hresult, self.stage = hresult.upper().replace("0X", "0x"), stage

    @property
    def needs_admin(self) -> bool:
        return self.hresult in ADMIN_ONLY


# HRESULTs that mean "an administrator could do this": the elevated helper retries then.
ADMIN_ONLY = {"0x80240044": "only administrators can download this update (WU_E_PER_MACHINE_UPDATE_ACCESS_DENIED)",
              "0x80070005": "access denied (E_ACCESSDENIED)"}
KNOWN_HRESULTS = {**ADMIN_ONLY,
                  "0x8024402C": "Windows Update could not reach its servers (WU_E_PT_WINHTTP_NAME_NOT_RESOLVED)",
                  "0x80240438": "no route to the Windows Update service (WU_E_PT_ENDPOINT_UNREACHABLE)",
                  "0x8024001E": "the Windows Update service is shutting down or was stopped (WU_E_SERVICE_STOP)",
                  "0x80240022": "every update in the download failed (WU_E_ALL_UPDATES_FAILED)",
                  "0x80246007": "Windows Update has no downloaded copy to hand over (WU_E_DM_NOTDOWNLOADED)"}

FETCH_TIMEOUT = 1800               # a large GPU driver over a slow link
_FETCH_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$out = [ordered]@{ files = @(); error = $null; hresult = $null; stage = 'search'; downloaded = $false }
try {
  $session = New-Object -ComObject Microsoft.Update.Session
  $session.ClientApplicationID = 'driver-installer'
  $found = $session.CreateUpdateSearcher().Search("UpdateID='" + $env:SD_UPDATE_ID + "'")
  if ($found.Updates.Count -lt 1) { throw 'Windows Update no longer offers this update to this PC' }
  $u = $found.Updates.Item(0)
  try { if (-not $u.EulaAccepted) { $u.AcceptEula() } } catch { }
  $out.downloaded = [bool]$u.IsDownloaded
  if (-not $u.IsDownloaded) {
    $out.stage = 'download'
    $todo = New-Object -ComObject Microsoft.Update.UpdateColl
    [void]$todo.Add($u)
    $downloader = $session.CreateUpdateDownloader()
    $downloader.Updates = $todo
    $result = $downloader.Download()
    if ($result.ResultCode -notin 2, 3) {
      $hr = $result.GetUpdateResult(0).HResult
      $out.hresult = '0x{0:X8}' -f $hr
      throw ("the download ended with result {0}" -f $result.ResultCode)
    }
    $out.downloaded = $true
    # The object from before the download still says "not downloaded": look it up again,
    # or CopyFromCache fails with WU_E_DM_NOTDOWNLOADED.
    $again = $session.CreateUpdateSearcher().Search("UpdateID='" + $env:SD_UPDATE_ID + "'")
    if ($again.Updates.Count -gt 0) { $u = $again.Updates.Item(0) }
  }
  $out.stage = 'copy'
  $parts = @($u)
  if ($u.BundledUpdates.Count -gt 0) { $parts = @($u.BundledUpdates | ForEach-Object { $_ }) }
  foreach ($part in $parts) { $part.CopyFromCache($env:SD_DEST, $false) }
  $out.files = @(Get-ChildItem -LiteralPath $env:SD_DEST -Recurse -File |
                 ForEach-Object { [ordered]@{ path = $_.FullName; size = $_.Length } })
} catch {
  $out.error = $_.Exception.Message
  if (-not $out.hresult) { $out.hresult = '0x{0:X8}' -f $_.Exception.HResult }
}
$out | ConvertTo-Json -Depth 4 -Compress
"""


def title_version(title: str) -> str:
    """Driver version from a Windows Update title: "Intel - Net - 23.60.1.2" or "Intel net Driver Update (24.40.0.4)"."""
    m = _VERSION.search((title or "").strip())
    return m.group(1) if m else ""


def policy_notes(policy: dict | None) -> list[str]:
    """Plain-language reasons the machine's policy may hide driver updates."""
    notes = []
    p = policy or {}
    if p.get("ExcludeWUDriversInQualityUpdate") == 1:
        notes.append("policy ExcludeWUDriversInQualityUpdate=1: Windows Update is set not to offer drivers")
    if p.get("WUServer"):
        notes.append(f"updates come from a WSUS server ({p['WUServer']}), which decides which drivers are offered")
    if p.get("DoNotConnectToWindowsUpdateInternetLocations") == 1:
        notes.append("policy DoNotConnectToWindowsUpdateInternetLocations=1: Windows Update may not reach Microsoft")
    return notes


def search() -> dict:
    """Raw WUA search result: {"policy", "updates", "resultCode", "error"}."""
    data, problem = common.powershell_json(_SCRIPT, env={"SD_CRITERIA": SEARCH_CRITERIA}, timeout=TIMEOUT, strict=True)
    if problem:
        raise WindowsUpdateError(problem)
    if not isinstance(data, dict):
        raise WindowsUpdateError("unexpected Windows Update result")
    if data.get("error"):
        raise WindowsUpdateError(f"Windows Update search failed: {data['error']}")
    updates = data.get("updates") or []
    data["updates"] = updates if isinstance(updates, list) else [updates]
    return data


def explain_hresult(hresult: str) -> str:
    return KNOWN_HRESULTS.get(hresult.upper().replace("0X", "0x"), "")


def _agent_result(script: str, env: dict, update_id: str, failed_event: str, prefix: str = "") -> dict:
    """Run a fetch or install script; its JSON result, or WindowsUpdateError naming the step
    ({stage}), the HRESULT and what that HRESULT means."""
    data, problem = common.powershell_json(script, env=env, timeout=FETCH_TIMEOUT)
    if not isinstance(data, dict):
        raise WindowsUpdateError(problem or "unexpected answer from PowerShell")
    if data.get("error"):
        hresult, stage = str(data.get("hresult") or ""), str(data.get("stage") or "")
        known = explain_hresult(hresult)
        common.audit(failed_event, update=update_id, stage=stage, hresult=hresult, error=str(data["error"]))
        raise WindowsUpdateError(f"{prefix}{stage} step failed: {data['error']}" + (f" [{hresult}]" if hresult else "")
                                 + (f": {known}" if known else ""), hresult, stage)
    return data


def fetch_payload(update_id: str, dest_dir: Path, max_size: int) -> list[Path]:
    """Have the Windows Update Agent download one update and copy its files out of the WUA cache
    into dest_dir (empty, private). Returns every file it copied, whatever their names: a driver
    cabinet often has no .cab extension in the cache, and some updates arrive as several files or
    as loose .inf/.cat/.sys files. installer.build_package_dir turns them into one driver package.
    WUA checks every file against Microsoft-signed update metadata; the caller still checks the
    catalog signature and LOLDrivers. Raises WindowsUpdateError (needs_admin tells whether an
    administrator could succeed where this account could not)."""
    if not _GUID.match(update_id or ""):
        raise WindowsUpdateError("malformed update id")
    dest_dir.mkdir(parents=True, exist_ok=True)
    common.audit("wua.fetch.start", update=update_id, elevated=_elevated())
    data = _agent_result(_FETCH_SCRIPT, {"SD_UPDATE_ID": update_id, "SD_DEST": str(dest_dir)},
                         update_id, "wua.fetch.failed", "Windows Update Agent ")
    root = dest_dir.resolve()
    # Trust the folder, not the list the script printed: only regular files really inside it.
    files = sorted(f for f in root.rglob("*") if f.is_file() and not f.is_symlink() and root in f.resolve().parents)
    if not files:
        raise WindowsUpdateError("the Windows Update Agent copied no files for this update", stage="copy")
    total = sum(f.stat().st_size for f in files)
    if total > max_size:
        raise WindowsUpdateError(f"the update is larger than {max_size} bytes ({total})", stage="copy")
    common.audit("wua.fetch.done", update=update_id, files=[f"{f.relative_to(root)} ({f.stat().st_size})" for f in files][:20],
                 size=total, already_downloaded=bool(data.get("downloaded")))
    return files


_INSTALL_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$out = [ordered]@{ result = $null; reboot = $false; error = $null; hresult = $null; stage = 'search' }
try {
  $session = New-Object -ComObject Microsoft.Update.Session
  $session.ClientApplicationID = 'driver-installer'
  $found = $session.CreateUpdateSearcher().Search("UpdateID='" + $env:SD_UPDATE_ID + "'")
  if ($found.Updates.Count -lt 1) { throw 'Windows Update no longer offers this update to this PC' }
  $todo = New-Object -ComObject Microsoft.Update.UpdateColl
  [void]$todo.Add($found.Updates.Item(0))
  if (-not $found.Updates.Item(0).IsDownloaded) {
    $out.stage = 'download'
    $d = $session.CreateUpdateDownloader(); $d.Updates = $todo; [void]$d.Download()
  }
  $out.stage = 'install'
  $installer = $session.CreateUpdateInstaller()
  $installer.Updates = $todo
  $r = $installer.Install()
  $out.result = [int]$r.ResultCode
  $out.reboot = [bool]$r.RebootRequired
  if ($r.ResultCode -notin 2, 3) { $out.hresult = '0x{0:X8}' -f $r.GetUpdateResult(0).HResult; throw ("the install ended with result {0}" -f $r.ResultCode) }
} catch {
  $out.error = $_.Exception.Message
  if (-not $out.hresult) { $out.hresult = '0x{0:X8}' -f $_.Exception.HResult }
}
$out | ConvertTo-Json -Compress
"""


def install_update(update_id: str) -> str:
    """Install one update with the Windows Update Agent's own installer (as administrator).
    Returns "installed" or "reboot-required"; raises WindowsUpdateError."""
    if not _GUID.match(update_id or ""):
        raise WindowsUpdateError("malformed update id")
    common.audit("wua.install.start", update=update_id)
    data = _agent_result(_INSTALL_SCRIPT, {"SD_UPDATE_ID": update_id}, update_id, "wua.install.failed")
    status = "reboot-required" if data.get("reboot") else "installed"
    common.audit("wua.install.done", update=update_id, result=data.get("result"), status=status)
    return status


def _elevated() -> bool:
    from .. import elevation
    try:
        return bool(elevation.is_admin())
    except Exception:                       # diagnostics only
        return False


def _device_index(devices: list[Device]) -> dict[str, Device]:
    """Upper-case Windows hardware or compatible ID (as WUA reports it) -> device."""
    index: dict[str, Device] = {}
    for device in devices:
        for hid in device.hardware_ids:
            if hid.startswith("raw:"):
                index.setdefault(hid[4:].upper(), device)
    return index


def to_package(update: dict, device: Device, version: str) -> dict:
    """Shaped like a manifest package; origin=windows-update. Download and digest are filled in
    by the verification step (catalog download dialog, else the URL WUA reported)."""
    uid = str(update["UpdateID"]).lower()
    hwid = str(update.get("DriverHardwareID") or "")
    norm = [h for h in normalise_windows_id(hwid) if not h.startswith("raw:")] if hwid else []
    urls = [u for u in update.get("Urls") or [] if str(u).lower().split("?")[0].endswith(".cab")]
    package = {
        "id": f"windowsupdate.{uid}", "origin": "windows-update", "update_id": uid,
        "name": str(update.get("Title") or device.name)[:200],
        "vendor": str(update.get("DriverProvider") or update.get("DriverManufacturer") or device.vendor or "Unknown"),
        "category": "driver", "version": version,
        "platform": {"os": "windows", "arch": [common.ARCH]},
        "hardware_ids": norm[:1] or [h for h in device.hardware_ids if not h.startswith("raw:")][:1] or ["raw:" + hwid.lower()],
        "matched_hardware_id": hwid, "id_confirmed": True,
        "artifact": {"url": urls[0] if urls else "", "filename": f"{uid}.cab",
                     "size": int(update.get("MaxDownloadSize") or 0), "sha256": "", "format": "cab",
                     "signature": {"type": "authenticode", "target": "catalog", "subject": trust.WINDOWS_UPDATE_SUBJECTS}},
        "install": {"method": "pnputil", "reboot_required": False},
        "upstream": {"source": "windows-update",
                     "reference_url": f"https://www.catalog.update.microsoft.com/ScopedViewInline.aspx?updateid={uid}"},
    }
    if update.get("DriverVerDate"):
        package["release_date"] = str(update["DriverVerDate"])
    return package


def discover(devices: list[Device], data: dict | None = None) -> tuple[list[tuple[Device, dict]], list[str]]:
    """(device, package) pairs for the drivers Windows Update offers, plus notes for the user.

    Each offered update is matched to a scanned device by the hardware ID Windows Update names;
    every update that is not turned into a package is logged with the reason."""
    data = data if data is not None else search()
    notes = policy_notes(data.get("policy"))
    index = _device_index(devices)
    found, skipped = [], []
    for update in data["updates"]:
        uid, title = str(update.get("UpdateID") or "").lower(), str(update.get("Title") or "")
        hwid = str(update.get("DriverHardwareID") or "").upper()
        version = title_version(title)
        device = index.get(hwid)
        reason = ("malformed update id" if not _GUID.match(uid)
                  else f"no scanned device has hardware ID {hwid or '(none)'}" if device is None
                  else "no version in the update title" if not version
                  else f"{version} is not newer than the installed {device.driver_version}"
                  if not is_newer(version, device.driver_version) else "")
        if reason:
            skipped.append({"title": title, "hardware_id": hwid, "reason": reason})
            continue
        found.append((device, to_package(update, device, version)))
    common.audit("wua.done", offered=len(data["updates"]), matched=len(found), skipped=skipped,
                 result=RESULT_CODES.get(data.get("resultCode"), data.get("resultCode")), policy=data.get("policy"),
                 notes=notes)
    return found, notes
