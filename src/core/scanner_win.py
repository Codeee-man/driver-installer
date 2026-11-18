"""Windows hardware and driver inventory from WMI.

Three classes are read and joined:

  Win32_PnPEntity        one row per device: PNPDeviceID, HardwareID[], ClassGuid, Service, problem code
  Win32_PnPSignedDriver  the driver package bound to a device: DriverVersion, DriverDate, InfName, signer
  Win32_SystemDriver     the kernel service behind Win32_PnPEntity.Service: .sys path, state

The WMI transport is pluggable so the parsing and matching logic can be tested
anywhere: `FixtureWmiSource` replays JSON captured from a real machine (see
tests/fixtures/wmi), `PyWmiSource` uses the `wmi` package (pywin32) when it is
installed, and `PowerShellWmiSource` needs nothing beyond Windows itself.
"""
from __future__ import annotations

import datetime as dt
import json
import re
from pathlib import Path
from typing import Protocol

from . import common
from .model import Device, normalise_windows_id

QUERIES: dict[str, tuple[str, ...]] = {
    "Win32_PnPEntity": ("Name", "PNPDeviceID", "HardwareID", "CompatibleID", "ClassGuid", "PNPClass",
                        "Manufacturer", "Service", "Status", "ConfigManagerErrorCode", "Present"),
    "Win32_PnPSignedDriver": ("DeviceID", "DeviceName", "DriverVersion", "DriverDate", "InfName",
                              "DriverProviderName", "Manufacturer", "IsSigned", "Signer", "ClassGuid", "HardWareID"),
    "Win32_SystemDriver": ("Name", "DisplayName", "PathName", "State", "StartMode", "ServiceType"),
}
PROBLEM_CODES = {1: "not configured", 10: "cannot start", 18: "reinstall the driver", 22: "disabled",
                 24: "not present or not working", 28: "no driver installed", 31: "driver failed to load",
                 39: "driver corrupted or missing", 43: "device reported a problem", 52: "driver signature not verified"}


class WmiSource(Protocol):
    def query(self, wmi_class: str) -> list[dict]: ...


class PowerShellWmiSource:
    """Get-CimInstance through Windows PowerShell. Class and property names come from QUERIES only."""

    def query(self, wmi_class: str) -> list[dict]:
        props = ",".join(QUERIES[wmi_class])
        script = ("$ErrorActionPreference='Stop'\n[Console]::OutputEncoding=[Text.Encoding]::UTF8\n"
                  f"ConvertTo-Json -InputObject @(Get-CimInstance -ClassName {wmi_class} | "
                  f"Select-Object {props}) -Depth 3 -Compress")
        res = common.powershell(script, timeout=300)
        if res is None or res.rc != 0:
            common.audit("wmi.query.failed", wmi_class=wmi_class, error=(res.stderr[:200] if res else "no powershell"))
            return []
        rows = json.loads(res.stdout or "[]")
        return rows if isinstance(rows, list) else [rows]


class PyWmiSource:
    """Same data through the `wmi` package (COM via pywin32), when it is installed."""

    def __init__(self):
        import wmi  # noqa: PLC0415 - optional dependency, Windows only
        self._conn = wmi.WMI()

    def query(self, wmi_class: str) -> list[dict]:
        props = QUERIES[wmi_class]
        rows = self._conn.query(f"SELECT {', '.join(props)} FROM {wmi_class}")
        return [{p: (list(v) if isinstance(v, tuple) else v) for p in props for v in [getattr(r, p, None)]}
                for r in rows]


class FixtureWmiSource:
    """Replays <dir>/<WmiClass>.json. Used by the tests and by --wmi-fixture for offline debugging."""

    def __init__(self, directory: Path):
        self.directory = Path(directory)

    def query(self, wmi_class: str) -> list[dict]:
        path = self.directory / f"{wmi_class}.json"
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else []


def default_source() -> WmiSource:
    try:
        return PyWmiSource()
    except Exception:  # package missing, or COM unavailable
        return PowerShellWmiSource()


def parse_wmi_date(value) -> str:
    """ISO date from the three shapes WMI dates arrive in:
    '/Date(1697760000000)/' (PowerShell 5 JSON), '20231020000000.000000-000' (CIM_DATETIME via COM),
    or an ISO string (PowerShell 7 JSON)."""
    if not value:
        return ""
    text = str(value)
    m = re.search(r"/Date\((-?\d+)\)/", text)
    if m:
        return (dt.datetime(1970, 1, 1) + dt.timedelta(milliseconds=int(m.group(1)))).date().isoformat()
    m = re.match(r"(\d{4})(\d{2})(\d{2})\d{6}\.", text)
    if m:
        return "-".join(m.groups())
    m = re.match(r"(\d{4}-\d{2}-\d{2})", text)
    return m.group(1) if m else ""


def _as_list(value) -> list[str]:
    if value is None:
        return []
    return [str(v) for v in value] if isinstance(value, (list, tuple)) else [str(value)]


def build_devices(entities: list[dict], signed: list[dict], services: list[dict]) -> list[Device]:
    """Pure join of the three WMI result sets into Device records."""
    by_device = {str(r["DeviceID"]).upper(): r for r in signed if r.get("DeviceID")}
    by_service = {str(r["Name"]).lower(): r for r in services if r.get("Name")}
    devices: list[Device] = []
    for ent in entities:
        pnp_id = ent.get("PNPDeviceID")
        if not pnp_id:
            continue
        drv = by_device.get(str(pnp_id).upper(), {})
        version = str(drv.get("DriverVersion") or "")
        problem = int(ent.get("ConfigManagerErrorCode") or 0)
        if not version and not problem:
            continue  # software/virtual node with no driver package: nothing to update
        ids: list[str] = []
        # Compatible IDs too: Windows (and Windows Update) also match drivers on them.
        raws = [str(pnp_id), *_as_list(ent.get("HardwareID")), *_as_list(drv.get("HardWareID")),
                *_as_list(ent.get("CompatibleID"))]
        for raw in raws:
            for hid in normalise_windows_id(raw):
                if hid not in ids:
                    ids.append(hid)
        service = str(ent.get("Service") or "")
        svc = by_service.get(service.lower(), {})
        dev = Device(
            name=str(ent.get("Name") or drv.get("DeviceName") or pnp_id),
            vendor=str(ent.get("Manufacturer") or drv.get("Manufacturer") or ""),
            kind=str(ent.get("PNPClass") or "other").lower(),
            hardware_ids=ids, driver=service, driver_version=version, address=str(pnp_id),
            source="WMI", class_guid=str(ent.get("ClassGuid") or drv.get("ClassGuid") or "").lower(),
            inf=str(drv.get("InfName") or ""), driver_file=str(svc.get("PathName") or ""),
            driver_date=parse_wmi_date(drv.get("DriverDate")),
            signed=drv.get("IsSigned") if isinstance(drv.get("IsSigned"), bool) else None,
        )
        if drv.get("DriverProviderName"):
            dev.notes.append(f"provider {drv['DriverProviderName']}"
                             + (f", dated {dev.driver_date}" if dev.driver_date else ""))
        if dev.signed is False:
            dev.notes.append("installed driver is NOT signed")
        if problem:
            dev.notes.append(f"problem code {problem}: {PROBLEM_CODES.get(problem, 'see Device Manager')}")
        if svc and str(svc.get("State") or "").lower() not in ("running", ""):
            dev.notes.append(f"driver service '{service}' is {svc['State']}")
        devices.append(dev)
    return devices


def scan(source: WmiSource | None = None) -> list[Device]:
    src = source or default_source()
    common.audit("scan.windows.start", transport=type(src).__name__)
    rows = {cls: src.query(cls) for cls in QUERIES}
    devices = build_devices(rows["Win32_PnPEntity"], rows["Win32_PnPSignedDriver"], rows["Win32_SystemDriver"])
    common.audit("scan.windows.done", entities=len(rows["Win32_PnPEntity"]), devices=len(devices))
    return devices


def discover_updates(devices: list[Device], client=None, progress=None) -> list[tuple[Device, dict]]:
    """Find newer drivers for scanned devices in the Microsoft Update Catalog, by hardware ID.

    This is what lets a Windows machine work without a SafeDriver manifest. Returns
    (device, package) pairs; each package is shaped like a manifest package and marked
    origin=ms-catalog. See core/discovery/ms_catalog.py for what is sent and what is trusted."""
    from .discovery import ms_catalog
    return ms_catalog.discover(devices, client, progress=progress)
