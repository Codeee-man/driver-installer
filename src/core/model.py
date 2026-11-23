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
    # Every device instance this entry stands for (Windows PNPDeviceIDs, Linux bus addresses).
    # Empty or one entry: a single device. More: identical devices merged by dedupe_devices().
    instances: list[str] = dataclasses.field(default_factory=list)

    @property
    def count(self) -> int:
        """How many identical device instances this entry stands for (at least 1)."""
        return max(len(self.instances), 1)


# Itemised verification. Every update carries one record per check, in this order, so a
# front end can say exactly what was and was not verified.
PASSED, FAILED, SKIPPED, NOT_APPLICABLE = "passed", "failed", "skipped", "not_applicable"
# Not done yet, but the elevated installer must pass it before it changes anything, and refuses
# the update otherwise (Windows Update drivers that only an administrator may download).
AT_INSTALL = "at_install"
CHECK_ORDER = ("sha256", "manifest", "blocklist", "publisher")
CHECK_LABELS = {
    "sha256": "SHA-256 integrity",
    "manifest": "Ed25519 manifest signature",
    "blocklist": "LOLDrivers BYOVD check",
    "publisher": "Publisher signature (Authenticode / GPG)",
}
CHECK_SHORT = {"sha256": "SHA-256", "manifest": "Ed25519", "blocklist": "LOLDrivers", "publisher": "publisher signature"}


@dataclasses.dataclass
class Check:
    key: str                        # one of CHECK_ORDER
    state: str                      # passed | failed | skipped | not_applicable | at_install
    reason: str = ""

    @property
    def label(self) -> str:
        return CHECK_LABELS.get(self.key, self.key)


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
    checks: list[Check] = dataclasses.field(default_factory=list)

    def set_check(self, key: str, state: str, reason: str = "") -> None:
        """Record one check result, replacing any earlier one, keeping CHECK_ORDER."""
        others = {c.key: c for c in self.checks if c.key != key}
        others[key] = Check(key, state, reason)
        # assign a new list in one step: the GUI may be reading it from another thread
        self.checks = [others[k] for k in CHECK_ORDER if k in others]

    def check(self, key: str) -> Check | None:
        return next((c for c in self.checks if c.key == key), None)


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


# ------------------------------------------------------------- duplicates
def _base_id(device: Device) -> str:
    """The device's model, not its instance: the first hardware ID that is not its own instance
    path (PNPDeviceID ends in a per-instance suffix: ...\\_0, ...\\_1, ...\\3&11583659&0&FF);
    for PCI and USB that is the normalised pci:/usb: ID, otherwise the most specific HardwareID."""
    own = "raw:" + device.address.lower()
    return next((h for h in device.hardware_ids if h != own), "")


def duplicate_key(device: Device) -> tuple | None:
    """Devices with equal keys are the same hardware with the same driver in the same state:
    same name, model (base hardware ID), driver package (INF) and installed version, and the
    same notes (a problem code on one instance keeps it apart). None: never merged (fwupd
    devices are installed by their own address; nothing to compare without a model ID or INF)."""
    if device.kind == "fwupd":
        return None
    base, inf = _base_id(device), device.inf.lower()
    if not (base or inf):
        return None
    name = " ".join(device.name.split()).casefold()
    return (name, device.kind, base or inf, inf, device.driver_version, device.driver_date,
            device.signed, tuple(device.notes))


def dedupe_devices(devices: list[Device]) -> list[Device]:
    """One entry per distinct device, in first-seen order. Windows lists, for example, every
    logical CPU as its own device (16 x "12th Gen Intel(R) Core(TM) i5-12500H" with the same
    driver); they become one Device whose `instances` holds all 16 instance IDs and whose
    hardware_ids holds the union of theirs, so update matching and pnputil (which installs a
    driver on every device it matches) still cover each instance."""
    merged: dict[tuple, Device] = {}
    out: list[Device] = []
    for device in devices:
        key = duplicate_key(device)
        first = merged.get(key) if key is not None else None
        if first is None:
            device.instances = list(dict.fromkeys(device.instances or ([device.address] if device.address else [])))
            out.append(device)
            if key is not None:
                merged[key] = device
            continue
        for inst in device.instances or [device.address]:
            if inst and inst not in first.instances:
                first.instances.append(inst)
        for hid in device.hardware_ids:
            if hid not in first.hardware_ids:
                first.hardware_ids.append(hid)
    return out
