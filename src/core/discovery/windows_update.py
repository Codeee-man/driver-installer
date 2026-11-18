"""Windows driver discovery through the Windows Update Agent (WUA) COM API.

This asks Windows itself which driver updates it offers for this PC, the same list Settings ›
Windows Update › Optional updates › Driver updates shows:

    Microsoft.Update.Session -> CreateUpdateSearcher().Search("IsInstalled=0 and Type='Driver' and IsHidden=0")

It runs through Windows PowerShell 5.1 (no pywin32 needed) as the ordinary user; searching
needs no administrator rights. The search honours the machine's update policy (WSUS, "exclude
drivers from quality updates"), and that policy is recorded with the results, because it is the
most common reason for an empty list.

Trust: what WUA reports is only a pointer. Each update is fetched as its .cab, from a Microsoft
download host, and goes through the same checks as catalog drivers: published digest,
LOLDrivers, and a .cat signed by Microsoft's hardware publisher (enforced again by the elevated
helper). Windows Update and the Microsoft Update Catalog share update IDs, so the catalog's
download dialog supplies the file's digest; the URL WUA reports is used if the catalog has none.
The COM search was verified on a real Windows runner (it returned no drivers there: a virtual
machine with Windows Update blocked by policy); results on physical hardware are untested.
"""
from __future__ import annotations

import json
import re

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
    """The Windows Update Agent could not be queried."""


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
    res = common.powershell(_SCRIPT, env={"SD_CRITERIA": SEARCH_CRITERIA}, timeout=TIMEOUT)
    if res is None:
        raise WindowsUpdateError("Windows PowerShell is not available")
    if res.rc != 0 or not res.stdout.strip():
        raise WindowsUpdateError(common.clean_powershell_error(res.stderr) or f"PowerShell exited with {res.rc}")
    try:
        data = json.loads(res.stdout)
    except ValueError as exc:
        raise WindowsUpdateError(f"unreadable Windows Update result: {exc}") from exc
    if not isinstance(data, dict):
        raise WindowsUpdateError("unexpected Windows Update result")
    if data.get("error"):
        raise WindowsUpdateError(f"Windows Update search failed: {data['error']}")
    updates = data.get("updates") or []
    data["updates"] = updates if isinstance(updates, list) else [updates]
    return data


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
                     "signature": {"type": "authenticode", "target": "catalog", "subject": trust.MS_WHQL_SUBJECT}},
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
