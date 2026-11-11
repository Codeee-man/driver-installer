"""Linux discovery: firmware from LVFS through fwupd, proprietary drivers through the distro.

Firmware (UEFI, NVMe, docks, vendor devices)
    fwupd is asked over its D-Bus API (org.freedesktop.fwupd: GetDevices, GetUpgrades) when the
    `dbus` Python module is present, otherwise through `fwupdmgr --json`. fwupd downloads LVFS
    metadata and firmware itself and verifies their signatures; SafeDriver only lists what
    fwupd offers and later asks fwupd to apply it.

Proprietary / DKMS drivers (mostly GPUs)
    The distro's own tool decides what fits the hardware, in this order:
      ubuntu-drivers devices          Ubuntu and derivatives
      mhwd -l --pci                   Manjaro
      apt-cache / dnf / pacman        NVIDIA GPUs still on nouveau: nvidia-driver, akmod-nvidia, nvidia
    Packages come from repositories already configured on the machine and are verified by the
    package manager. Nothing is downloaded by SafeDriver.

The elevated helper does not trust a package name handed to it: it calls
`recommended_packages()` again as root and installs only what that returns.
"""
from __future__ import annotations

import dataclasses
import json
import re
from typing import Protocol

from .. import common
from ..model import Device

FWUPD_BUS, FWUPD_PATH, FWUPD_IFACE = "org.freedesktop.fwupd", "/", "org.freedesktop.fwupd"
FLAG_UPDATABLE = 1 << 1
NVIDIA_PACKAGES = {"apt-get": "nvidia-driver", "dnf": "akmod-nvidia", "pacman": "nvidia"}
PACKAGE_NAME = re.compile(r"^[a-z0-9][a-z0-9+._-]{0,127}$")


# ------------------------------------------------------------------- fwupd
class FwupdBackend(Protocol):
    name: str

    def devices(self) -> list[dict]: ...
    def upgrades(self, device_id: str) -> list[dict]: ...


def _plain(value):
    """dbus-python types -> plain Python."""
    if isinstance(value, dict):
        return {str(k): _plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(v) for v in value]
    if isinstance(value, bool):
        return bool(value)
    if isinstance(value, int):
        return int(value)
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    return str(value) if value is not None else None


class DbusFwupd:
    """fwupd over the system bus. Needs the `dbus` module (python3-dbus)."""
    name = "fwupd D-Bus"

    def __init__(self):
        import dbus  # noqa: PLC0415 - optional dependency
        self._dbus = dbus
        proxy = dbus.SystemBus().get_object(FWUPD_BUS, FWUPD_PATH)
        self._iface = dbus.Interface(proxy, FWUPD_IFACE)

    def devices(self) -> list[dict]:
        return [_plain(d) for d in self._iface.GetDevices(timeout=60)]

    def upgrades(self, device_id: str) -> list[dict]:
        try:
            return [_plain(r) for r in self._iface.GetUpgrades(device_id, timeout=60)]
        except self._dbus.DBusException:      # NothingToDo / NotSupported: no upgrade for this device
            return []


class CliFwupd:
    """fwupd through `fwupdmgr --json` (fallback when the dbus module is missing)."""
    name = "fwupdmgr"

    def __init__(self):
        self._upgrades: dict[str, list[dict]] | None = None

    def devices(self) -> list[dict]:
        res = common.run(["fwupdmgr", "get-devices", "--json"])
        if not res or res.rc != 0:
            return []
        try:
            return json.loads(res.stdout).get("Devices", [])
        except ValueError:
            return []

    def upgrades(self, device_id: str) -> list[dict]:
        if self._upgrades is None:
            self._upgrades = {}
            res = common.run(["fwupdmgr", "get-updates", "--json"])     # exits 2 when nothing to do
            if res and res.stdout.strip():
                try:
                    for dev in json.loads(res.stdout).get("Devices", []):
                        self._upgrades[dev.get("DeviceId", "")] = dev.get("Releases", [])
                except ValueError:
                    pass
        return self._upgrades.get(device_id, [])


def fwupd_backend() -> FwupdBackend | None:
    try:
        return DbusFwupd()
    except Exception:                         # no dbus module, no system bus, or fwupd not installed
        return CliFwupd() if common.have("fwupdmgr") else None


def _updatable(dev: dict) -> bool:
    flags = dev.get("Flags")
    if isinstance(flags, int):
        return bool(flags & FLAG_UPDATABLE)
    return "updatable" in (flags or [])


def _checksums(release: dict) -> list[str]:
    value = release.get("Checksum") or []
    return [c.strip() for c in value.split(",")] if isinstance(value, str) else list(value)


def fwupd_inventory(backend: FwupdBackend | None = None, refresh: bool = False
                    ) -> tuple[list[Device], dict[str, dict]]:
    """(devices fwupd manages, {DeviceId: newest release available from LVFS})."""
    backend = backend or fwupd_backend()
    if backend is None:
        common.audit("fwupd.unavailable")
        return [], {}
    if refresh and common.have("fwupdmgr"):
        common.run(["fwupdmgr", "refresh"], timeout=180)    # LVFS metadata; fwupd verifies its signature
    devices, upgrades = [], {}
    for dev in backend.devices():
        device_id = str(dev.get("DeviceId") or "")
        if not device_id:
            continue
        devices.append(Device(name=str(dev.get("Name") or "fwupd device"), vendor=str(dev.get("Vendor") or ""),
                              kind="fwupd", hardware_ids=[f"fwupd:{g}" for g in dev.get("Guid") or []],
                              driver=str(dev.get("Plugin") or ""), driver_version=str(dev.get("Version") or ""),
                              address=device_id, source=backend.name))
        if _updatable(dev):
            releases = backend.upgrades(device_id)
            if releases:
                newest = dict(releases[0])
                newest["Checksum"] = _checksums(newest)
                upgrades[device_id] = newest
    common.audit("fwupd.inventory", backend=backend.name, devices=len(devices), upgrades=len(upgrades))
    return devices, upgrades


# ------------------------------------------------------ proprietary drivers
@dataclasses.dataclass
class Recommendation:
    package: str
    manager: str               # apt-get | dnf | pacman | mhwd
    tool: str                  # what recommended it
    hardware_id: str = ""      # pci:vvvv:dddd it is for, when known
    reason: str = ""


def _installed(manager: str, package: str) -> bool:
    if manager == "apt-get":
        res = common.run(["dpkg-query", "-W", "-f", "${Status}", package])
        return bool(res and res.rc == 0 and "install ok installed" in res.stdout)
    if manager == "dnf":
        res = common.run(["rpm", "-q", package])
        return bool(res and res.rc == 0)
    if manager == "pacman":
        res = common.run(["pacman", "-Qq", package])
        return bool(res and res.rc == 0)
    return False


def parse_ubuntu_drivers(output: str) -> list[tuple[str, str]]:
    """`ubuntu-drivers devices` -> [(pci:vvvv:dddd, recommended package)]."""
    out, hwid = [], ""
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("=="):
            hwid = ""
        m = re.match(r"modalias\s*:\s*pci:v0000([0-9A-Fa-f]{4})d0000([0-9A-Fa-f]{4})", line)
        if m:
            hwid = f"pci:{m.group(1).lower()}:{m.group(2).lower()}"
        m = re.match(r"driver\s*:\s*(\S+)\s+-\s+(.*)$", line)
        if m and "recommended" in m.group(2).split() and PACKAGE_NAME.match(m.group(1)):
            out.append((hwid, m.group(1)))
    return out


def parse_mhwd(output: str) -> list[tuple[str, str, bool]]:
    """`mhwd -l --pci` / `mhwd -li` -> [(pci id or "", config name, is free driver)]."""
    out, hwid = [], ""
    for line in output.splitlines():
        m = re.match(r">\s*\S+\s+\([0-9a-f]{4}:([0-9a-f]{4}):([0-9a-f]{4})\)", line.strip(), re.I)
        if m:
            hwid = f"pci:{m.group(1).lower()}:{m.group(2).lower()}"
            continue
        m = re.match(r"^\s*([a-z0-9][a-z0-9-]+)\s+\S+\s+(true|false)\s+PCI\s*$", line)
        if m:
            out.append((hwid, m.group(1), m.group(2) == "true"))
    return out


def _nvidia_gpus_without_driver(devices: list[Device]) -> list[Device]:
    return [d for d in devices if d.kind == "pci" and any(h.startswith("pci:10de:") for h in d.hardware_ids)
            and d.driver in ("nouveau", "") and re.search(r"VGA|3D|Display", d.name, re.I)]


def driver_recommendations(devices: list[Device]) -> list[Recommendation]:
    """Proprietary driver packages the distro recommends for this hardware and that are not installed."""
    recs: list[Recommendation] = []
    if common.have("ubuntu-drivers"):
        res = common.run(["ubuntu-drivers", "devices"], timeout=180)
        for hwid, package in parse_ubuntu_drivers(res.stdout) if res and res.rc == 0 else []:
            if not _installed("apt-get", package):
                recs.append(Recommendation(package, "apt-get", "ubuntu-drivers", hwid, "recommended by ubuntu-drivers"))
    elif common.have("mhwd"):
        listed = common.run(["mhwd", "-l", "--pci"], timeout=120)
        have = common.run(["mhwd", "-li"], timeout=120)
        installed = {name for _, name, _ in parse_mhwd(have.stdout)} if have and have.rc == 0 else set()
        done = set()
        for hwid, name, free in parse_mhwd(listed.stdout) if listed and listed.rc == 0 else []:
            if hwid in done:
                continue                      # configs are listed best-first per device
            done.add(hwid)
            if not free and name not in installed:
                recs.append(Recommendation(name, "mhwd", "mhwd", hwid, "first non-free config offered by mhwd"))
    else:
        gpus = _nvidia_gpus_without_driver(devices)
        manager = next((m for m in NVIDIA_PACKAGES if common.have(m)), None)
        if gpus and manager:
            package = NVIDIA_PACKAGES[manager]
            probe = {"apt-get": ["apt-cache", "policy", package], "dnf": ["dnf", "-q", "repoquery", package],
                     "pacman": ["pacman", "-Si", package]}[manager]
            res = common.run(probe, timeout=180)
            available = bool(res and res.rc == 0 and res.stdout.strip() and "Candidate: (none)" not in res.stdout)
            if available and not _installed(manager, package):
                hwid = next(h for h in gpus[0].hardware_ids if h.startswith("pci:10de:"))
                recs.append(Recommendation(package, manager, probe[0], hwid,
                                           "NVIDIA GPU is running without the proprietary driver"))
    unique = {}
    for rec in recs:
        unique.setdefault(rec.package, rec)
    common.audit("drivers.recommendations", packages=[f"{r.manager}:{r.package}" for r in unique.values()])
    return list(unique.values())


def recommended_packages(devices: list[Device]) -> dict[str, Recommendation]:
    """{package name: recommendation}. The elevated helper calls this itself before installing."""
    return {r.package: r for r in driver_recommendations(devices)}


def to_package(rec: Recommendation) -> dict:
    version = re.search(r"(\d+(?:\.\d+)*)$", rec.package)
    return {"id": f"distro.{rec.package}", "origin": "linux-repo", "name": f"{rec.package} ({rec.reason})",
            "vendor": "distribution", "category": "driver", "version": version.group(1) if version else "0",
            "platform": {"os": "linux", "arch": [common.ARCH]},
            "hardware_ids": [rec.hardware_id or "raw:" + rec.package],
            "install": {"method": "package-manager", "package_name": rec.package, "manager": rec.manager,
                        "reboot_required": True},
            "upstream": {"source": "distro", "reference_url": ""}}


def match_devices(recs: list[Recommendation], devices: list[Device]) -> list[tuple[Device, Recommendation]]:
    """Pair each recommendation with the device it is for (or a placeholder system device)."""
    pairs = []
    for rec in recs:
        device = next((d for d in devices if rec.hardware_id and rec.hardware_id in d.hardware_ids), None)
        pairs.append((device or Device(name="This computer", kind="system"), rec))
    return pairs
