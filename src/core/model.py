"""Data model and version comparison."""
from __future__ import annotations

import dataclasses
import re


@dataclasses.dataclass
class Device:
    name: str
    vendor: str = ""
    kind: str = ""                  # pci | usb | cpu | firmware | fwupd | <Windows PNP class>
    hardware_ids: list[str] = dataclasses.field(default_factory=list)
    driver: str = ""                # Linux module / Windows service name
    driver_version: str = ""
    address: str = ""               # PCI slot, USB bus:dev, PNPDeviceID, fwupd DeviceId
    source: str = ""
    notes: list[str] = dataclasses.field(default_factory=list)
    class_guid: str = ""            # Windows INF class GUID, lower case with braces
    inf: str = ""                   # Windows: oemNN.inf
    driver_file: str = ""           # Windows: path of the .sys behind the service
    driver_date: str = ""           # ISO date
    signed: bool | None = None


@dataclasses.dataclass
class Update:
    device: Device
    name: str
    installed: str
    available: str
    source: str
    sha256: str = ""
    package: dict | None = None     # manifest entry; None for updates fwupd found itself
    status: str = "pending"         # pending | verified | failed | delegated
    detail: str = ""
    path: str = ""                  # verified file in the quarantine directory
    signature_file: str = ""        # detached GPG signature, if any


def parse_version(text: str | None) -> tuple[int, ...]:
    """Turn a version string into a comparable tuple; () means "unknown".

    Handles Windows DriverVersion (31.0.15.3623), package versions with epochs
    and revisions (1:550.120-1ubuntu1), a leading v, and hex microcode
    revisions (0xf8). Trailing zero components are ignored, so 1.2 == 1.2.0.
    """
    t = (text or "").strip().lower()
    if re.fullmatch(r"0x[0-9a-f]+", t):
        return (0, int(t, 16))
    t = t.lstrip("v")
    epoch = 0
    m = re.match(r"(\d+):(.+)", t)
    if m:
        epoch, t = int(m.group(1)), m.group(2)
    main = re.split(r"[-+~\s]", t, maxsplit=1)[0]
    parts: list[int] = []
    for comp in main.split("."):
        m = re.match(r"\d+", comp)
        if not m:
            break
        parts.append(int(m.group(0)))
    if not parts:
        return ()
    while len(parts) > 1 and parts[-1] == 0:
        parts.pop()
    return (epoch, *parts)


def compare_versions(a: str | None, b: str | None) -> int:
    """-1, 0 or 1. Unknown versions sort lowest."""
    ta, tb = parse_version(a), parse_version(b)
    return (ta > tb) - (ta < tb)


def is_newer(available: str, installed: str | None) -> bool:
    """True when `available` should be offered over `installed` (unknown installed -> offer)."""
    have = parse_version(installed)
    return not have or parse_version(available) > have


_WIN_PCI = re.compile(r"PCI\\VEN_([0-9A-F]{4})&DEV_([0-9A-F]{4})(?:&SUBSYS_([0-9A-F]{4})([0-9A-F]{4}))?", re.I)
_WIN_USB = re.compile(r"USB\\VID_([0-9A-F]{4})&PID_([0-9A-F]{4})", re.I)


def normalise_windows_id(raw: str) -> list[str]:
    """PCI\\VEN_8086&DEV_2725&SUBSYS_00248086 -> [pci:8086:2725, pci:8086:2725:8086:0024, raw:...]."""
    out: list[str] = []
    m = _WIN_PCI.search(raw)
    if m:
        ven, dev, sdev, sven = (g.lower() if g else g for g in m.groups())
        out.append(f"pci:{ven}:{dev}")
        if sven:
            out.append(f"pci:{ven}:{dev}:{sven}:{sdev}")
    m = _WIN_USB.search(raw)
    if m:
        out.append(f"usb:{m.group(1).lower()}:{m.group(2).lower()}")
    out.append("raw:" + raw.lower())
    return out
