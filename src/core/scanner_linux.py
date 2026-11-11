"""Linux hardware inventory: lspci/lsusb/lshw with sysfs fallbacks, CPU microcode, fwupd, DKMS."""
from __future__ import annotations

import json
import platform
import re
from pathlib import Path

from . import common
from .discovery import linux_lvfs
from .model import Device

_NAME_CODE = re.compile(r"^(.*?)\s*\[([0-9a-f]{4})\]$", re.I)


def _read(path) -> str:
    try:
        return Path(path).read_text(errors="replace").strip()
    except OSError:
        return ""


def _module_version(driver: str) -> str:
    if not driver:
        return ""
    return _read(f"/sys/module/{driver.replace('-', '_')}/version") or f"in-kernel {platform.release()}"


def _split_code(text: str) -> tuple[str, str]:
    m = _NAME_CODE.match(text.strip())
    return (m.group(1), m.group(2).lower()) if m else (text.strip(), "")


def scan_pci() -> list[Device]:
    devices = []
    res = common.run(["lspci", "-Dvmmnnk"])
    if res and res.rc == 0:
        for block in res.stdout.strip().split("\n\n"):
            f = dict(line.split(":\t", 1) for line in block.splitlines() if ":\t" in line)
            (vname, ven), (dname, dev) = _split_code(f.get("Vendor", "")), _split_code(f.get("Device", ""))
            if not ven or not dev:
                continue
            ids = [f"pci:{ven}:{dev}"]
            sven, sdev = _split_code(f.get("SVendor", ""))[1], _split_code(f.get("SDevice", ""))[1]
            if sven and sdev:
                ids.append(f"pci:{ven}:{dev}:{sven}:{sdev}")
            drv = f.get("Driver", "")
            devices.append(Device(name=f"{dname} ({_split_code(f.get('Class', ''))[0]})", vendor=vname, kind="pci",
                                  hardware_ids=ids, driver=drv, driver_version=_module_version(drv),
                                  address=f.get("Slot", ""), source="lspci"))
        return devices
    for d in sorted(Path("/sys/bus/pci/devices").glob("*")):
        ven, dev = _read(d / "vendor")[2:], _read(d / "device")[2:]
        if not ven:
            continue
        drv = (d / "driver").resolve().name if (d / "driver").exists() else ""
        devices.append(Device(name=f"PCI device {ven}:{dev} (class {_read(d / 'class')})", kind="pci",
                              hardware_ids=[f"pci:{ven}:{dev}"], driver=drv,
                              driver_version=_module_version(drv), address=d.name, source="sysfs"))
    return devices


def scan_usb() -> list[Device]:
    devices = []
    res = common.run(["lsusb"])
    if res and res.rc == 0:
        for m in re.finditer(r"^Bus (\d+) Device (\d+): ID ([0-9a-f]{4}):([0-9a-f]{4})\s*(.*)$", res.stdout, re.M):
            bus, num, ven, pid, name = m.groups()
            devices.append(Device(name=name or f"USB device {ven}:{pid}", kind="usb",
                                  hardware_ids=[f"usb:{ven}:{pid}"], address=f"{bus}:{num}", source="lsusb"))
        return devices
    for d in sorted(Path("/sys/bus/usb/devices").glob("*")):
        ven, pid = _read(d / "idVendor"), _read(d / "idProduct")
        if ven and pid:
            devices.append(Device(name=_read(d / "product") or f"USB device {ven}:{pid}",
                                  vendor=_read(d / "manufacturer"), kind="usb",
                                  hardware_ids=[f"usb:{ven}:{pid}"], address=d.name, source="sysfs"))
    return devices


def scan_cpu(cpuinfo: str | None = None) -> list[Device]:
    """CPU microcode revision (x86)."""
    info = {}
    for line in (cpuinfo if cpuinfo is not None else _read("/proc/cpuinfo")).splitlines():
        if not line.strip():
            break
        key, _, val = line.partition(":")
        info[key.strip()] = val.strip()
    if "microcode" not in info:
        return []
    try:
        sig = "{:02x}-{:02x}-{:02x}".format(int(info["cpu family"]), int(info["model"]), int(info["stepping"]))
    except (KeyError, ValueError):
        return []
    vendor = info.get("vendor_id", "").lower()
    pkg = {"genuineintel": "intel-microcode / intel-ucode", "authenticamd": "amd64-microcode / amd-ucode"}.get(vendor)
    dev = Device(name=info.get("model name", "CPU") + " (microcode)", vendor=info.get("vendor_id", ""), kind="cpu",
                 hardware_ids=[f"cpu:{vendor}:{sig}"], driver="microcode", driver_version=info["microcode"],
                 source="/proc/cpuinfo")
    if pkg:
        dev.notes.append(f"updated through the distro package {pkg}")
    return [dev]


def scan_system() -> list[Device]:
    dmi = Path("/sys/class/dmi/id")
    vendor, product = _read(dmi / "sys_vendor"), _read(dmi / "product_name")
    bios = " ".join(x for x in (_read(dmi / "bios_version"), _read(dmi / "bios_date")) if x)
    res = common.run(["lshw", "-json", "-quiet", "-class", "system"])
    if res and res.rc == 0 and res.stdout.strip():
        try:
            data = json.loads(res.stdout)
            node = data[0] if isinstance(data, list) else data
            vendor, product = vendor or node.get("vendor", ""), product or node.get("product", "")
        except (ValueError, IndexError, AttributeError):
            pass
    if not (vendor or product or bios):
        return []
    return [Device(name=f"System firmware: {vendor} {product}".strip(), vendor=_read(dmi / "bios_vendor") or vendor,
                   kind="firmware",
                   hardware_ids=[f"dmi:{vendor.lower()}:{product.lower()}"] if vendor and product else [],
                   driver="UEFI/BIOS", driver_version=bios, source="DMI/lshw")]


def annotate_proprietary(devices: list[Device]) -> None:
    dkms = {}
    res = common.run(["dkms", "status"])
    if res and res.rc == 0:
        for line in res.stdout.splitlines():
            m = re.match(r"^([\w.+-]+)[/,]\s*([\w.+~-]+)", line)
            if m:
                dkms[m.group(1).lower()] = m.group(2)
    nvidia = _read("/sys/module/nvidia/version")
    for dev in devices:
        if dev.kind != "pci":
            continue
        if dev.driver.lower() in dkms:
            dev.notes.append(f"DKMS module {dev.driver} {dkms[dev.driver.lower()]}")
        if any(h.startswith("pci:10de:") for h in dev.hardware_ids) and (
                dev.driver in ("nvidia", "nouveau") or re.search(r"VGA|3D|Display", dev.name, re.I)):
            if nvidia and dev.driver == "nvidia":
                dev.driver_version = nvidia
                dev.notes.append("proprietary NVIDIA driver; updated through the distro package manager")
            elif dev.driver in ("nouveau", ""):
                dev.notes.append("NVIDIA GPU without the proprietary driver")


def scan() -> tuple[list[Device], dict[str, dict]]:
    fw, upgrades = linux_lvfs.fwupd_inventory()        # D-Bus when available, else fwupdmgr
    devices = scan_pci() + scan_usb() + scan_cpu() + scan_system() + fw
    annotate_proprietary(devices)
    return devices, upgrades
