#!/usr/bin/env python3
"""SafeDriver proof of concept (driver-installer, Phase 1).

Scan hardware on Windows or Linux, match it against a signed manifest,
download packages with mandatory SHA-256 verification, and show the workflow
in a small dark GUI.

This PoC NEVER installs anything. The apply step only prints the snapshot and
install commands the real tool would run.

    python safedriver_poc.py --scan [--json]
    python safedriver_poc.py --dry-run   --manifest M --sig M.sig --pubkey HEX
    python safedriver_poc.py --update-all --manifest M --sig M.sig --pubkey HEX
    python safedriver_poc.py --gui [--demo]
    python safedriver_poc.py --self-test
    python safedriver_poc.py --verify-log

Requires Python 3.9+. Optional: `cryptography` (manifest signatures; without
it manifests are refused), `PySide6` (GUI).
"""
from __future__ import annotations

import argparse
import base64
import dataclasses
import datetime as dt
import hashlib
import hmac
import http.server
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import urllib.parse
import urllib.request
from pathlib import Path

APP = "SafeDriver"
VERSION = "0.1.0-poc"
IS_WIN = platform.system() == "Windows"
IS_LINUX = platform.system() == "Linux"
OS_NAME = "windows" if IS_WIN else "linux" if IS_LINUX else platform.system().lower()
ARCH = {"amd64": "x86_64", "x86_64": "x86_64", "arm64": "aarch64", "aarch64": "aarch64",
        "i386": "x86", "i686": "x86", "x86": "x86"}.get(platform.machine().lower(), platform.machine().lower())
CHUNK = 1 << 20


class VerificationError(Exception):
    """Raised whenever a manifest, download or signature fails a check."""


# --------------------------------------------------------------------------
# Audit log: append-only JSON Lines, each record chained to the previous hash
# --------------------------------------------------------------------------
def state_dir() -> Path:
    if IS_WIN:
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
        return base / APP
    return Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state")) / "safedriver"


class AuditLog:
    GENESIS = "0" * 64

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._prev, self._seq = self.GENESIS, 0
        self.listeners = []  # callables(record) for the GUI log pane
        if self.path.exists():
            last = None
            with self.path.open("rb") as fh:
                for line in fh:
                    if line.strip():
                        last = line
            if last:
                try:
                    rec = json.loads(last)
                    self._prev, self._seq = rec["hash"], rec["seq"] + 1
                except (ValueError, KeyError):
                    pass  # verify_chain() will report the damage

    @staticmethod
    def _digest(rec: dict) -> str:
        body = {k: v for k, v in rec.items() if k != "hash"}
        return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    def write(self, event: str, **data) -> None:
        with self._lock:
            rec = {"seq": self._seq, "ts": dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds"),
                   "event": event, "data": data, "prev": self._prev}
            rec["hash"] = self._digest(rec)
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec, sort_keys=True) + "\n")
            self._prev, self._seq = rec["hash"], self._seq + 1
        for cb in list(self.listeners):
            cb(rec)

    @classmethod
    def verify_chain(cls, path: Path) -> tuple[bool, str]:
        prev, n = cls.GENESIS, 0
        with Path(path).open(encoding="utf-8") as fh:
            for n, line in enumerate(fh, 1):
                try:
                    rec = json.loads(line)
                except ValueError:
                    return False, f"line {n}: not valid JSON"
                if rec.get("prev") != prev or rec.get("hash") != cls._digest(rec):
                    return False, f"line {n}: chain broken (record edited, removed or reordered)"
                prev = rec["hash"]
        return True, f"{n} records, chain intact"


AUDIT: AuditLog  # set in main()


def run(cmd: list[str], timeout: int = 90, env: dict | None = None) -> subprocess.CompletedProcess | None:
    """Run a command without a shell. Returns None if missing or it failed to start."""
    exe = shutil.which(cmd[0])
    if not exe:
        AUDIT.write("exec.unavailable", program=cmd[0])
        return None
    full_env = {**os.environ, "LC_ALL": "C", **(env or {})}
    flags = 0x08000000 if IS_WIN else 0  # CREATE_NO_WINDOW
    try:
        proc = subprocess.run([exe, *cmd[1:]], capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=timeout, env=full_env, creationflags=flags)
    except (OSError, subprocess.TimeoutExpired) as exc:
        AUDIT.write("exec.error", program=cmd[0], error=str(exc))
        return None
    AUDIT.write("exec", program=cmd[0], args=[a[:120] for a in cmd[1:]], rc=proc.returncode)
    return proc


def powershell(script: str, env: dict | None = None, timeout: int = 180) -> str | None:
    encoded = base64.b64encode(script.encode("utf-16-le")).decode()
    proc = run(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                "-EncodedCommand", encoded], timeout=timeout, env=env)
    return proc.stdout if proc and proc.returncode == 0 else None


# --------------------------------------------------------------------------
# Hardware model
# --------------------------------------------------------------------------
@dataclasses.dataclass
class Device:
    name: str
    vendor: str = ""
    kind: str = ""                 # pci | usb | cpu | firmware | fwupd | other
    hardware_ids: list[str] = dataclasses.field(default_factory=list)
    driver: str = ""
    driver_version: str = ""
    address: str = ""
    source: str = ""               # which probe produced this entry
    notes: list[str] = dataclasses.field(default_factory=list)


_WIN_PCI = re.compile(r"PCI\\VEN_([0-9A-F]{4})&DEV_([0-9A-F]{4})(?:&SUBSYS_([0-9A-F]{4})([0-9A-F]{4}))?", re.I)
_WIN_USB = re.compile(r"USB\\VID_([0-9A-F]{4})&PID_([0-9A-F]{4})", re.I)


def normalise_windows_id(raw: str) -> list[str]:
    """PCI\\VEN_8086&DEV_2725&SUBSYS_00248086 -> pci:8086:2725 (+ subsystem form)."""
    out = []
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


# ------------------------------ Windows -----------------------------------
_WIN_SCAN = r"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$drv = @{}
Get-CimInstance Win32_PnPSignedDriver | ForEach-Object { if ($_.DeviceID) { $drv[$_.DeviceID] = $_ } }
$rows = Get-CimInstance Win32_PnPEntity | Where-Object { $_.PNPDeviceID } | ForEach-Object {
  $s = $drv[$_.PNPDeviceID]
  [pscustomobject]@{
    Name = $_.Name; PNPDeviceID = $_.PNPDeviceID; HardwareID = @($_.HardwareID)
    Class = $_.PNPClass; Manufacturer = $_.Manufacturer; ErrorCode = $_.ConfigManagerErrorCode
    DriverVersion = $s.DriverVersion; Inf = $s.InfName; Provider = $s.DriverProviderName
    DriverDate = $(if ($s.DriverDate) { $s.DriverDate.ToString('yyyy-MM-dd') })
    IsSigned = $s.IsSigned; Signer = $s.Signer
  }
}
ConvertTo-Json -InputObject @($rows) -Depth 3 -Compress
"""


def scan_windows() -> list[Device]:
    out = powershell(_WIN_SCAN)
    if not out:
        AUDIT.write("scan.windows.failed")
        return []
    devices = []
    for row in json.loads(out):
        version, err = row.get("DriverVersion") or "", row.get("ErrorCode") or 0
        if not version and not err:
            continue  # software/virtual node with no driver package: nothing to update
        ids: list[str] = []
        for raw in [row.get("PNPDeviceID") or "", *(row.get("HardwareID") or [])]:
            for hid in normalise_windows_id(raw) if raw else []:
                if hid not in ids:
                    ids.append(hid)
        dev = Device(name=row.get("Name") or row["PNPDeviceID"], vendor=row.get("Manufacturer") or "",
                     kind=(row.get("Class") or "other").lower(), hardware_ids=ids,
                     driver=row.get("Inf") or "", driver_version=version,
                     address=row["PNPDeviceID"], source="WMI Win32_PnPEntity")
        if row.get("DriverDate"):
            dev.notes.append(f"driver date {row['DriverDate']}, provider {row.get('Provider') or '?'}")
        if row.get("IsSigned") is False:
            dev.notes.append("installed driver is NOT signed")
        if err:
            dev.notes.append(f"device problem code {err}" + (" (no driver installed)" if err == 28 else ""))
        devices.append(dev)
    return devices


# ------------------------------- Linux ------------------------------------
def _read(path: str | Path) -> str:
    try:
        return Path(path).read_text(errors="replace").strip()
    except OSError:
        return ""


def _module_version(driver: str) -> str:
    if not driver:
        return ""
    return _read(f"/sys/module/{driver.replace('-', '_')}/version") or f"in-kernel {platform.release()}"


_NAME_CODE = re.compile(r"^(.*?)\s*\[([0-9a-f]{4})\]$", re.I)


def _split_code(text: str) -> tuple[str, str]:
    m = _NAME_CODE.match(text.strip())
    return (m.group(1), m.group(2).lower()) if m else (text.strip(), "")


def scan_linux_pci() -> list[Device]:
    devices = []
    proc = run(["lspci", "-Dvmmnnk"])
    if proc and proc.returncode == 0:
        for block in proc.stdout.strip().split("\n\n"):
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
    for d in sorted(Path("/sys/bus/pci/devices").glob("*")):  # fallback: sysfs only, no names
        ven, dev = _read(d / "vendor")[2:], _read(d / "device")[2:]
        if not ven:
            continue
        drv = (d / "driver").resolve().name if (d / "driver").exists() else ""
        devices.append(Device(name=f"PCI device {ven}:{dev} (class {_read(d / 'class')})", kind="pci",
                              hardware_ids=[f"pci:{ven}:{dev}"], driver=drv,
                              driver_version=_module_version(drv), address=d.name, source="sysfs"))
    return devices


def scan_linux_usb() -> list[Device]:
    devices = []
    proc = run(["lsusb"])
    if proc and proc.returncode == 0:
        for m in re.finditer(r"^Bus (\d+) Device (\d+): ID ([0-9a-f]{4}):([0-9a-f]{4})\s*(.*)$", proc.stdout, re.M):
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


def scan_linux_cpu() -> list[Device]:
    """CPU microcode revision from /proc/cpuinfo (x86; other arches have no such field)."""
    info = {}
    for line in _read("/proc/cpuinfo").splitlines():
        if not line.strip():
            break  # first logical CPU is enough
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


def scan_linux_system() -> list[Device]:
    """System firmware identity from DMI, enriched by lshw when available."""
    dmi = Path("/sys/class/dmi/id")
    vendor, product = _read(dmi / "sys_vendor"), _read(dmi / "product_name")
    bios = " ".join(x for x in (_read(dmi / "bios_version"), _read(dmi / "bios_date")) if x)
    proc = run(["lshw", "-json", "-quiet", "-class", "system"])
    if proc and proc.returncode == 0 and proc.stdout.strip():
        try:
            data = json.loads(proc.stdout)
            node = data[0] if isinstance(data, list) else data
            vendor, product = vendor or node.get("vendor", ""), product or node.get("product", "")
        except (ValueError, IndexError, AttributeError):
            pass
    if not (vendor or product or bios):
        return []
    return [Device(name=f"System firmware: {vendor} {product}".strip(), vendor=_read(dmi / "bios_vendor") or vendor,
                   kind="firmware", hardware_ids=[f"dmi:{vendor.lower()}:{product.lower()}"] if vendor and product else [],
                   driver="UEFI/BIOS", driver_version=bios, source="DMI/lshw")]


def scan_linux_fwupd() -> tuple[list[Device], dict[str, dict]]:
    """Devices known to fwupd and pending upgrades. (PoC: fwupdmgr --json; production: D-Bus.)"""
    devices, upgrades = [], {}
    proc = run(["fwupdmgr", "get-devices", "--json"])
    if not proc or proc.returncode != 0:
        return devices, upgrades
    try:
        listed = json.loads(proc.stdout).get("Devices", [])
    except ValueError:
        return devices, upgrades
    for d in listed:
        devices.append(Device(name=d.get("Name", "fwupd device"), vendor=d.get("Vendor", ""), kind="fwupd",
                              hardware_ids=[f"fwupd:{g}" for g in d.get("Guid", [])], driver=d.get("Plugin", ""),
                              driver_version=d.get("Version", ""), address=d.get("DeviceId", ""), source="fwupd"))
    proc = run(["fwupdmgr", "get-updates", "--json"])  # exits 2 when there is nothing to do
    if proc and proc.stdout.strip():
        try:
            for d in json.loads(proc.stdout).get("Devices", []):
                if d.get("Releases"):
                    upgrades[d.get("DeviceId", "")] = d["Releases"][0]
        except ValueError:
            pass
    return devices, upgrades


def annotate_linux_proprietary(devices: list[Device]) -> None:
    """Flag out-of-tree / proprietary drivers (NVIDIA etc.) via sysfs and DKMS."""
    dkms = {}
    proc = run(["dkms", "status"])
    if proc and proc.returncode == 0:
        for line in proc.stdout.splitlines():
            m = re.match(r"^([\w.+-]+)[/,]\s*([\w.+~-]+)", line)
            if m:
                dkms[m.group(1).lower()] = m.group(2)
    nvidia = _read("/sys/module/nvidia/version")
    for dev in devices:
        if dev.kind != "pci":
            continue
        if dev.driver.lower() in dkms:
            dev.notes.append(f"DKMS module {dev.driver} {dkms[dev.driver.lower()]}")
        if "pci:10de:" in " ".join(dev.hardware_ids) and (dev.driver in ("nvidia", "nouveau") or re.search(r"VGA|3D|Display", dev.name, re.I)):
            if nvidia and dev.driver == "nvidia":
                dev.driver_version = nvidia
                dev.notes.append("proprietary NVIDIA driver; update through the distro package manager")
            elif dev.driver in ("nouveau", ""):
                dev.notes.append("NVIDIA GPU without the proprietary driver; see `ubuntu-drivers devices`, "
                                 "RPM Fusion or the distro's nvidia package")


def scan() -> tuple[list[Device], dict[str, dict]]:
    """Return (devices, fwupd_upgrades). The only entry point the CLI and GUI use."""
    AUDIT.write("scan.start", os=OS_NAME, arch=ARCH)
    upgrades: dict[str, dict] = {}
    if IS_WIN:
        devices = scan_windows()
    elif IS_LINUX:
        fw, upgrades = scan_linux_fwupd()
        devices = scan_linux_pci() + scan_linux_usb() + scan_linux_cpu() + scan_linux_system() + fw
        annotate_linux_proprietary(devices)
    else:
        raise SystemExit(f"{platform.system()} is not supported")
    AUDIT.write("scan.done", devices=len(devices), fwupd_upgrades=len(upgrades))
    return devices, upgrades


# --------------------------------------------------------------------------
# Signed manifest
# --------------------------------------------------------------------------
_SHA256 = re.compile(r"^[a-f0-9]{64}$")


def load_manifest(raw: bytes, signature_b64: bytes, pubkey_hex: str, *, check_rollback: bool = True) -> dict:
    """Verify the detached Ed25519 signature over the exact bytes, then freshness and shape."""
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:  # fail closed: no crypto library means no manifest
        raise VerificationError("the 'cryptography' package is required to verify manifests") from exc
    try:
        key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey_hex))
        key.verify(base64.b64decode(signature_b64, validate=True), raw)
    except (InvalidSignature, ValueError) as exc:
        AUDIT.write("manifest.rejected", reason="bad signature")
        raise VerificationError("manifest signature is invalid") from exc
    manifest = json.loads(raw)
    if not str(manifest.get("schema_version", "")).startswith("1."):
        raise VerificationError("unsupported manifest schema version")
    expires = dt.datetime.fromisoformat(manifest["expires"].replace("Z", "+00:00"))
    if expires <= dt.datetime.now(dt.timezone.utc):
        AUDIT.write("manifest.rejected", reason="expired", expires=manifest["expires"])
        raise VerificationError(f"manifest expired on {manifest['expires']}")
    seq_file = state_dir() / "manifest.sequence"
    if check_rollback:
        last = int(_read(seq_file) or 0)
        if manifest["sequence"] < last:
            AUDIT.write("manifest.rejected", reason="rollback", sequence=manifest["sequence"], last=last)
            raise VerificationError(f"manifest sequence {manifest['sequence']} is older than {last} (rollback)")
        seq_file.parent.mkdir(parents=True, exist_ok=True)
        seq_file.write_text(str(manifest["sequence"]))
    for pkg in manifest["packages"]:
        art = pkg["artifact"]
        if not _SHA256.match(art["sha256"]) or not isinstance(art["size"], int) or art["size"] < 1:
            raise VerificationError(f"package {pkg.get('id')}: malformed sha256 or size")
    AUDIT.write("manifest.accepted", sequence=manifest["sequence"], packages=len(manifest["packages"]),
                sha256=hashlib.sha256(raw).hexdigest())
    return manifest


def version_key(text: str) -> tuple[int, ...]:
    return tuple(int(n) for n in re.findall(r"\d+", text or ""))


@dataclasses.dataclass
class Update:
    device: Device
    name: str
    installed: str
    available: str
    source: str
    sha256: str = ""
    package: dict | None = None        # manifest entry, or None for fwupd-managed updates
    status: str = "pending"            # pending | verified | failed | delegated
    detail: str = ""
    path: str = ""


def find_updates(devices: list[Device], manifest: dict | None, fwupd_upgrades: dict[str, dict]) -> list[Update]:
    updates = []
    for dev in devices:
        rel = fwupd_upgrades.get(dev.address) if dev.kind == "fwupd" else None
        if rel:
            digest = next((c for c in rel.get("Checksum", []) if len(c) == 64), "")
            updates.append(Update(dev, rel.get("Name", dev.name), dev.driver_version, rel.get("Version", "?"),
                                  "fwupd / LVFS", digest, None, "delegated",
                                  "fwupd verifies this against LVFS-signed metadata"))
    for pkg in (manifest or {}).get("packages", []):
        plat = pkg["platform"]
        if plat["os"] != OS_NAME or ARCH not in plat["arch"]:
            continue
        wanted = set(pkg["hardware_ids"])
        for dev in devices:
            if wanted.isdisjoint(dev.hardware_ids):
                continue
            have = version_key(dev.driver_version) if dev.driver_version and "in-kernel" not in dev.driver_version else ()
            if have and have >= version_key(pkg["version"]):
                continue
            updates.append(Update(dev, pkg["name"], dev.driver_version or "unknown", pkg["version"],
                                  pkg["upstream"]["source"], pkg["artifact"]["sha256"], pkg))
    AUDIT.write("plan", updates=[{"device": u.device.name, "to": u.available, "source": u.source} for u in updates])
    return updates


# --------------------------------------------------------------------------
# Secure download: HTTPS only, size-capped, SHA-256 before anything touches it
# --------------------------------------------------------------------------
def _check_url(url: str, allow_loopback_http: bool) -> None:
    parts = urllib.parse.urlsplit(url)
    if parts.scheme == "https":
        return
    if allow_loopback_http and parts.scheme == "http" and parts.hostname in ("127.0.0.1", "localhost", "::1"):
        return  # demo / self-test only
    raise VerificationError(f"refusing non-HTTPS URL: {url}")


def _opener(allow_loopback_http: bool) -> urllib.request.OpenerDirector:
    class HttpsOnlyRedirects(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            _check_url(newurl, allow_loopback_http)
            AUDIT.write("net.redirect", to=newurl, code=code)
            return super().redirect_request(req, fp, code, msg, headers, newurl)
    opener = urllib.request.build_opener(HttpsOnlyRedirects)
    opener.addheaders = [("User-Agent", f"{APP}/{VERSION}")]  # no identifiers, no telemetry
    return opener


def secure_download(url: str, expected_sha256: str, expected_size: int, dest_dir: Path, filename: str,
                    *, allow_loopback_http: bool = False, progress=None) -> Path:
    """Download to a private quarantine dir and return the path ONLY if size and SHA-256 match.

    On any failure the partial file is deleted and VerificationError is raised.
    """
    if not _SHA256.match(expected_sha256):
        raise VerificationError("manifest sha256 is malformed")
    _check_url(url, allow_loopback_http)
    dest_dir.mkdir(parents=True, exist_ok=True)
    if not IS_WIN:
        os.chmod(dest_dir, 0o700)
    safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", Path(filename).name) or "package.bin"
    fd, tmp = tempfile.mkstemp(dir=dest_dir, prefix=".partial-")  # 0600, never executable
    digest, total = hashlib.sha256(), 0
    AUDIT.write("net.request", url=url, expect_sha256=expected_sha256, expect_size=expected_size)
    try:
        with os.fdopen(fd, "wb") as out, _opener(allow_loopback_http).open(url, timeout=30) as resp:
            while chunk := resp.read(CHUNK):
                total += len(chunk)
                if total > expected_size:
                    raise VerificationError(f"download exceeds the declared size of {expected_size} bytes")
                digest.update(chunk)
                out.write(chunk)
                if progress:
                    progress(total, expected_size)
            out.flush()
            os.fsync(out.fileno())
        actual = digest.hexdigest()
        if total != expected_size:
            raise VerificationError(f"size mismatch: got {total} bytes, manifest says {expected_size}")
        if not hmac.compare_digest(actual, expected_sha256):
            raise VerificationError(f"SHA-256 MISMATCH: got {actual}, manifest says {expected_sha256}")
    except Exception as exc:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        AUDIT.write("download.rejected", url=url, reason=str(exc), purged=not os.path.exists(tmp))
        if isinstance(exc, VerificationError):
            raise
        raise VerificationError(f"download failed: {exc}") from exc
    final = dest_dir / f"{expected_sha256[:16]}-{safe_name}"
    os.replace(tmp, final)
    if not IS_WIN:
        os.chmod(final, 0o400)
    AUDIT.write("download.verified", url=url, sha256=actual, size=total, path=str(final))
    return final


# --------------------------------------------------------------------------
# Publisher signatures
# --------------------------------------------------------------------------
_AUTHENTICODE = r"""
$s = Get-AuthenticodeSignature -LiteralPath $env:SD_FILE
[pscustomobject]@{ Status = $s.Status.ToString(); Subject = $s.SignerCertificate.Subject
                   Thumbprint = $s.SignerCertificate.Thumbprint } | ConvertTo-Json -Compress
"""


def verify_authenticode(path: Path, subject: str, thumbprint: str | None = None) -> None:
    out = powershell(_AUTHENTICODE, env={"SD_FILE": str(path)})  # path via env: no quoting or injection issues
    info = json.loads(out) if out else {}
    ok = (info.get("Status") == "Valid" and subject.lower() in (info.get("Subject") or "").lower()
          and (not thumbprint or (info.get("Thumbprint") or "").upper() == thumbprint.upper()))
    AUDIT.write("signature.authenticode", file=str(path), ok=ok, **{k: info.get(k) for k in ("Status", "Subject")})
    if not ok:
        raise VerificationError(f"Authenticode check failed (status {info.get('Status')}, signer {info.get('Subject')})")


def verify_gpg(path: Path, signature: Path, keyring: Path, fingerprint: str) -> None:
    proc = run(["gpgv", "--keyring", str(keyring), "--status-fd", "1", str(signature), str(path)])
    valid = re.search(r"^\[GNUPG:\] VALIDSIG ([0-9A-F]+)", proc.stdout, re.M) if proc and proc.returncode == 0 else None
    ok = bool(valid) and valid.group(1).upper() == fingerprint.upper()
    AUDIT.write("signature.gpg", file=str(path), ok=ok)
    if not ok:
        raise VerificationError("GPG signature check failed or signer is not the pinned key")


# --------------------------------------------------------------------------
# Workflow steps shared by the CLI and the GUI
# --------------------------------------------------------------------------
@dataclasses.dataclass
class Context:
    manifest: dict | None = None
    quarantine: Path = dataclasses.field(default_factory=lambda: state_dir() / "quarantine")
    allow_loopback_http: bool = False
    gpg_keyring: Path | None = None
    demo: bool = False


def verify_update(update: Update, ctx: Context, progress=None) -> None:
    """Download and verify one update. Sets update.status; never raises."""
    if update.package is None:
        return  # fwupd-managed: fwupd does its own verification at install time
    art = update.package["artifact"]
    try:
        path = secure_download(art["url"], art["sha256"], art["size"], ctx.quarantine, art["filename"],
                               allow_loopback_http=ctx.allow_loopback_http, progress=progress)
        sig = art["signature"]
        if ctx.demo:
            detail = "SHA-256 OK (demo payload: publisher signature step skipped)"
        elif sig["type"] == "authenticode":
            verify_authenticode(path, sig["subject"], sig.get("certificate_thumbprint"))
            detail = "SHA-256 OK, Authenticode OK"
        elif sig["type"] == "gpg":
            if not ctx.gpg_keyring:
                raise VerificationError("no pinned GPG keyring configured (--gpg-keyring)")
            sig_path = ctx.quarantine / (path.name + ".sig")
            _check_url(sig["signature_url"], ctx.allow_loopback_http)
            with _opener(ctx.allow_loopback_http).open(sig["signature_url"], timeout=30) as resp:
                sig_path.write_bytes(resp.read(1 << 16))
            verify_gpg(path, sig_path, ctx.gpg_keyring, sig["fingerprint"])
            detail = "SHA-256 OK, GPG OK"
        else:
            detail = f"SHA-256 OK, signature delegated to {sig['verifier']}"
        update.status, update.detail, update.path = "verified", detail, str(path)
    except VerificationError as exc:
        for leftover in ctx.quarantine.glob(f"{art['sha256'][:16]}-*"):
            leftover.unlink(missing_ok=True)  # purge if the signature step failed after the hash passed
        update.status, update.detail, update.path = "failed", f"{exc} - file purged", ""


def snapshot_command() -> list[str] | None:
    label = f"{APP} before driver update"
    if IS_WIN:
        return ["powershell", "-NoProfile", "-Command",
                f"Checkpoint-Computer -Description '{label}' -RestorePointType MODIFY_SETTINGS"]
    if shutil.which("timeshift"):
        return ["timeshift", "--create", "--comments", label, "--scripted"]
    if shutil.which("snapper"):
        return ["snapper", "create", "--type", "pre", "--print-number", "--description", label]
    return None


def install_plan(updates: list[Update]) -> list[str]:
    """Human-readable plan. The PoC prints it; it does not execute it."""
    ready = [u for u in updates if u.status in ("verified", "delegated")]
    if not ready:
        return ["Nothing verified, nothing to apply."]
    snap = snapshot_command()
    lines = ["[elevated] " + " ".join(snap) if snap else
             "!! No restore-point tool found (Timeshift/snapper). The real tool would ask for explicit confirmation."]
    for u in ready:
        if u.package is None:
            lines.append(f"[elevated] fwupdmgr update {u.device.address}")
            continue
        method, inst = u.package["install"]["method"], u.package["install"]
        if method == "pnputil":
            lines += [f"expand -F:* {u.path} <extract-dir>",
                      f"[elevated] pnputil /add-driver <extract-dir>\\{inst.get('inf_path', '*.inf')} /install"]
        elif method == "fwupd":
            lines.append(f"[elevated] fwupdmgr install {u.path}")
        else:
            lines.append(f"[elevated] <package manager> install {inst.get('package_name', u.path)}")
        if inst.get("reboot_required"):
            lines.append(f"   reboot required for {u.name}")
    AUDIT.write("apply.dry_run", plan=lines)
    return lines


# --------------------------------------------------------------------------
# Demo and self-test (local loopback server, throwaway signing key)
# --------------------------------------------------------------------------
def _serve(directory: Path) -> tuple[http.server.ThreadingHTTPServer, str]:
    class Quiet(http.server.SimpleHTTPRequestHandler):
        def log_message(self, *args):
            pass
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), lambda *a, **k: Quiet(*a, directory=str(directory), **k))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


def _sign(manifest: dict):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key = Ed25519PrivateKey.generate()
    raw = json.dumps(manifest, indent=1).encode()
    pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return raw, base64.b64encode(key.sign(raw)), pub.hex()


def _demo_package(i: int, hwid: str, name: str, base: str, payload: bytes, sha: str) -> dict:
    fname = f"demo-{i}.cab"
    return {"id": f"demo.package.{i}", "name": name, "vendor": "Demo", "category": "driver", "version": "999.0.0",
            "platform": {"os": OS_NAME, "arch": [ARCH]}, "hardware_ids": [hwid],
            "artifact": {"url": f"{base}/{fname}", "filename": fname, "size": len(payload), "sha256": sha,
                         "format": "cab", "signature": {"type": "delegated", "verifier": "fwupd"}},
            "install": {"method": "pnputil" if IS_WIN else "package-manager", "reboot_required": False},
            "upstream": {"source": "vendor", "reference_url": "https://example.invalid/demo"}}


def _manifest_shell(packages: list[dict], expires_in_days: int = 7, sequence: int = 1) -> dict:
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    return {"schema_version": "1.0", "sequence": sequence, "generated": now.isoformat().replace("+00:00", "Z"),
            "expires": (now + dt.timedelta(days=expires_in_days)).isoformat().replace("+00:00", "Z"),
            "publisher": {"name": "DEMO - throwaway key, fake payloads"},
            "signing": {"algorithm": "ed25519", "key_id": "0" * 16}, "packages": packages}


def build_demo(devices: list[Device], workdir: Path) -> Context:
    """Fake manifest for up to two detected devices: one honest package, one with a wrong hash."""
    server, base = _serve(workdir)
    packages = []
    for i, dev in enumerate([d for d in devices if d.hardware_ids][:2]):
        payload = os.urandom(256 * 1024)
        (workdir / f"demo-{i}.cab").write_bytes(payload)
        sha = hashlib.sha256(payload if i == 0 else payload + b"tampered").hexdigest()
        label = "DEMO good package" if i == 0 else "DEMO tampered package"
        packages.append(_demo_package(i, dev.hardware_ids[0], f"{label} for {dev.name[:40]}", base, payload, sha))
    raw, sig, pub = _sign(_manifest_shell(packages))
    ctx = Context(manifest=load_manifest(raw, sig, pub, check_rollback=False), quarantine=workdir / "quarantine",
                  allow_loopback_http=True, demo=True)
    ctx._server = server  # keep alive
    return ctx


def self_test() -> int:
    """Exercise the verification pipeline end to end. Hardware independent."""
    results = []

    def check(name, fn, expect_error=None):
        try:
            fn()
            ok, msg = expect_error is None, "accepted"
        except VerificationError as exc:
            ok, msg = bool(expect_error) and expect_error in str(exc), str(exc)[:70]
        results.append(ok)
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}: {msg}")

    with tempfile.TemporaryDirectory() as tmp:
        root, quarantine = Path(tmp) / "www", Path(tmp) / "q"
        root.mkdir()
        payload = os.urandom(3 * CHUNK + 123)
        (root / "good.cab").write_bytes(payload)
        (root / "big.cab").write_bytes(payload + b"x" * 4096)
        sha = hashlib.sha256(payload).hexdigest()
        server, base = _serve(root)
        dl = lambda name, digest, size: secure_download(f"{base}/{name}", digest, size, quarantine, name,
                                                        allow_loopback_http=True)
        leftovers = lambda: [p.name for p in quarantine.glob("*")] if quarantine.exists() else []

        check("correct hash is accepted", lambda: dl("good.cab", sha, len(payload)))
        kept = leftovers()
        check("wrong hash is rejected", lambda: dl("good.cab", "0" * 64, len(payload)), "SHA-256 MISMATCH")
        check("oversized download is cut off", lambda: dl("big.cab", sha, len(payload)), "exceeds the declared size")
        check("short download is rejected", lambda: dl("good.cab", sha, len(payload) + 1), "size mismatch")
        ok = leftovers() == kept and len(kept) == 1
        results.append(ok)
        print(f"  [{'PASS' if ok else 'FAIL'}] rejected files were purged: quarantine holds {leftovers()}")
        check("plain http to a remote host is refused",
              lambda: secure_download("http://example.invalid/x.cab", sha, 1, quarantine, "x.cab"), "non-HTTPS")
        check("http loopback refused outside demo mode",
              lambda: secure_download(f"{base}/good.cab", sha, len(payload), quarantine, "g.cab"), "non-HTTPS")

        pkgs = [_demo_package(0, "pci:1234:5678", "t", base, payload, sha)]
        raw, sig, pub = _sign(_manifest_shell(pkgs))
        check("signed manifest is accepted", lambda: load_manifest(raw, sig, pub, check_rollback=False))
        check("edited manifest is rejected",
              lambda: load_manifest(raw.replace(sha.encode(), b"0" * 64), sig, pub, check_rollback=False), "signature is invalid")
        _, _, other_pub = _sign({})
        check("manifest signed by another key is rejected",
              lambda: load_manifest(raw, sig, other_pub, check_rollback=False), "signature is invalid")
        raw2, sig2, pub2 = _sign(_manifest_shell(pkgs, expires_in_days=-1))
        check("expired manifest is rejected", lambda: load_manifest(raw2, sig2, pub2, check_rollback=False), "expired")
        server.shutdown()

    chain_ok, chain_msg = AuditLog.verify_chain(AUDIT.path)
    results.append(chain_ok)
    print(f"  [{'PASS' if chain_ok else 'FAIL'}] audit log: {chain_msg}")
    print(f"\n{sum(results)}/{len(results)} checks passed")
    return 0 if all(results) else 1


# --------------------------------------------------------------------------
# GUI (PySide6). Scan -> Review updates & hashes -> Apply (dry run)
# --------------------------------------------------------------------------
STYLE = """
* { font-family: 'Segoe UI', 'Inter', 'Noto Sans', sans-serif; font-size: 13px; color: #d7dce2; }
QMainWindow, QWidget { background: #14171c; }
QLabel#title { font-size: 18px; font-weight: 600; color: #f2f4f7; }
QLabel#step { color: #6b7684; padding: 4px 10px; border-radius: 10px; background: #1b2027; }
QLabel#step[active="true"] { color: #0f1216; background: #5eead4; font-weight: 600; }
QLabel#banner { padding: 8px 12px; border-radius: 6px; background: #3b1620; color: #fda4af; }
QTableWidget { background: #181c22; border: 1px solid #252b33; border-radius: 6px; gridline-color: transparent;
               selection-background-color: #222831; alternate-background-color: #1b2027; }
QHeaderView::section { background: #181c22; color: #8793a1; border: none; border-bottom: 1px solid #252b33;
                       padding: 6px; font-weight: 600; }
QPlainTextEdit { background: #101317; border: 1px solid #252b33; border-radius: 6px; color: #8793a1;
                 font-family: 'Cascadia Mono', 'DejaVu Sans Mono', monospace; font-size: 11px; }
QPushButton { background: #222831; border: 1px solid #303844; border-radius: 6px; padding: 8px 16px; }
QPushButton:hover { background: #2a323d; }
QPushButton:disabled { color: #4b5563; background: #181c22; border-color: #222831; }
QPushButton#primary { background: #5eead4; color: #0f1216; border: none; font-weight: 600; }
QPushButton#primary:disabled { background: #1f3b38; color: #4b6b66; }
"""


def run_gui(ctx: Context, workdir: Path, shot: str | None = None) -> int:
    from PySide6 import QtCore, QtGui, QtWidgets

    class Worker(QtCore.QThread):
        done = QtCore.Signal(object)
        tick = QtCore.Signal(int)

        def __init__(self, fn):
            super().__init__()
            self.fn = fn

        def run(self):
            try:
                self.done.emit(self.fn(self))
            except Exception as exc:  # shown in the banner, never swallowed
                self.done.emit(exc)

    class Window(QtWidgets.QMainWindow):
        log_line = QtCore.Signal(str)
        COLS = ["", "Device", "Installed", "Available", "Source", "SHA-256 (from signed manifest)", "Status"]

        def __init__(self):
            super().__init__()
            self.setWindowTitle(f"{APP} {VERSION}")
            self.resize(1080, 640)
            self.devices, self.updates, self.worker = [], [], None
            root = QtWidgets.QWidget()
            self.setCentralWidget(root)
            lay = QtWidgets.QVBoxLayout(root)
            lay.setContentsMargins(18, 16, 18, 16)
            lay.setSpacing(12)

            head = QtWidgets.QHBoxLayout()
            title = QtWidgets.QLabel(APP + ("  -  demo data" if ctx.demo else ""))
            title.setObjectName("title")
            head.addWidget(title)
            head.addStretch()
            self.steps = []
            for text in ("1  Scan", "2  Review updates & hashes", "3  Apply"):
                lab = QtWidgets.QLabel(text)
                lab.setObjectName("step")
                self.steps.append(lab)
                head.addWidget(lab)
            lay.addLayout(head)

            self.banner = QtWidgets.QLabel()
            self.banner.setObjectName("banner")
            self.banner.setWordWrap(True)
            self.banner.hide()
            lay.addWidget(self.banner)

            self.table = QtWidgets.QTableWidget(0, len(self.COLS))
            self.table.setHorizontalHeaderLabels(self.COLS)
            self.table.verticalHeader().hide()
            self.table.setAlternatingRowColors(True)
            self.table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
            self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
            hh = self.table.horizontalHeader()
            hh.setSectionResizeMode(QtWidgets.QHeaderView.ResizeToContents)
            hh.setSectionResizeMode(1, QtWidgets.QHeaderView.Interactive)
            hh.setSectionResizeMode(6, QtWidgets.QHeaderView.Stretch)
            self.table.setColumnWidth(1, 330)
            self.table.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
            lay.addWidget(self.table, 3)

            self.log = QtWidgets.QPlainTextEdit(readOnly=True)
            self.log.setMaximumBlockCount(500)
            self.log.setLineWrapMode(QtWidgets.QPlainTextEdit.NoWrap)
            lay.addWidget(self.log, 1)

            row = QtWidgets.QHBoxLayout()
            self.status = QtWidgets.QLabel("Ready. Nothing runs until you press Scan.")
            row.addWidget(self.status, 1)
            self.btn_scan = QtWidgets.QPushButton("Scan")
            self.btn_verify = QtWidgets.QPushButton("Download && verify selected")
            self.btn_apply = QtWidgets.QPushButton("Apply selected (dry run)")
            for b in (self.btn_scan, self.btn_verify, self.btn_apply):
                row.addWidget(b)
            self.btn_scan.setObjectName("primary")
            self.btn_verify.setEnabled(False)
            self.btn_apply.setEnabled(False)
            lay.addLayout(row)

            self.btn_scan.clicked.connect(self.do_scan)
            self.btn_verify.clicked.connect(self.do_verify)
            self.btn_apply.clicked.connect(self.do_apply)
            self.log_line.connect(self.log.appendPlainText)
            self._listener = lambda rec: self.log_line.emit(
                f"{rec['ts'][11:19]}  {rec['event']:<20} {json.dumps(rec['data'])[:150]}")
            AUDIT.listeners.append(self._listener)
            self.set_step(0)

        # -- helpers
        def set_step(self, index):
            for i, lab in enumerate(self.steps):
                lab.setProperty("active", "true" if i == index else "false")
                lab.style().unpolish(lab)
                lab.style().polish(lab)

        def alert(self, text):
            self.banner.setText(text)
            self.banner.setVisible(bool(text))

        def busy(self, fn, then):
            for b in (self.btn_scan, self.btn_verify, self.btn_apply):
                b.setEnabled(False)
            self.worker = Worker(fn)
            self.worker.done.connect(then)
            self.worker.start()

        def cell(self, text, colour=None, mono=False):
            item = QtWidgets.QTableWidgetItem(text)
            if colour:
                item.setForeground(QtGui.QColor(colour))
            if mono:
                item.setFont(QtGui.QFont("DejaVu Sans Mono", 9))
            return item

        def refresh(self):
            pending = {id(u.device) for u in self.updates}
            others = [d for d in self.devices if id(d) not in pending]
            self.table.setRowCount(len(self.updates) + len(others))
            colours = {"verified": "#5eead4", "failed": "#fb7185", "delegated": "#93c5fd", "pending": "#fbbf24"}
            for r, u in enumerate(self.updates):
                box = QtWidgets.QTableWidgetItem()
                box.setFlags(QtCore.Qt.ItemIsUserCheckable | QtCore.Qt.ItemIsEnabled)
                old = self.table.item(r, 0)
                box.setCheckState(old.checkState() if old and old.flags() & QtCore.Qt.ItemIsUserCheckable
                                  else QtCore.Qt.Checked)
                self.table.setItem(r, 0, box)
                sha = f"{u.sha256[:20]}...{u.sha256[-8:]}" if u.sha256 else "-"
                values = [u.name, u.installed, u.available, u.source, sha,
                          u.detail if u.status != "pending" else "update available - not yet verified"]
                for c, val in enumerate(values, 1):
                    item = self.cell(val, colours[u.status] if c == 6 else None, mono=c == 5)
                    item.setToolTip(u.sha256 if c == 5 else val)
                    self.table.setItem(r, c, item)
            for r, d in enumerate(others, len(self.updates)):
                self.table.setItem(r, 0, self.cell(""))
                for c, val in enumerate([d.name, d.driver_version or "-", "-", d.source, "-",
                                         "; ".join(d.notes) or "no update offered"], 1):
                    self.table.setItem(r, c, self.cell(val, "#6b7684"))

        def selected(self):
            return [u for r, u in enumerate(self.updates) if self.table.item(r, 0).checkState() == QtCore.Qt.Checked]

        # -- steps
        def do_scan(self):
            self.alert("")
            self.status.setText("Scanning hardware...")

            def work(_):
                nonlocal ctx
                devices, upgrades = scan()
                if ctx.demo and ctx.manifest is None:
                    ctx = build_demo(devices, workdir)
                return devices, find_updates(devices, ctx.manifest, upgrades)
            self.busy(work, self.scan_done)

        def scan_done(self, result):
            self.btn_scan.setEnabled(True)
            if isinstance(result, Exception):
                return self.alert(f"Scan failed: {result}")
            self.devices, self.updates = result
            self.table.clearContents()
            self.refresh()
            self.set_step(1)
            self.btn_verify.setEnabled(bool(self.updates))
            hint = "" if ctx.manifest else "  No manifest loaded: only fwupd updates can be listed."
            self.status.setText(f"{len(self.devices)} devices, {len(self.updates)} updates available.{hint}")

        def do_verify(self):
            self.alert("")
            chosen = self.selected()
            self.status.setText(f"Downloading and verifying {len(chosen)} package(s)...")
            self.busy(lambda _: [verify_update(u, ctx) for u in chosen], self.verify_done)

        def verify_done(self, result):
            self.btn_scan.setEnabled(True)
            self.btn_verify.setEnabled(True)
            if isinstance(result, Exception):
                return self.alert(f"Verification step failed: {result}")
            self.refresh()
            failed = [u for u in self.updates if u.status == "failed"]
            if failed:
                self.alert("Verification failed for: " + "; ".join(u.name for u in failed) +
                           ". The downloaded file was deleted and will not be installed.")
            ready = [u for u in self.selected() if u.status in ("verified", "delegated")]
            self.btn_apply.setEnabled(bool(ready))
            self.status.setText(f"{len(ready)} verified and ready, {len(failed)} rejected.")

        def do_apply(self):
            self.set_step(2)
            self.log.appendPlainText("\n--- DRY RUN: the PoC does not install. The real tool would run: ---")
            for line in install_plan(self.selected()):
                self.log.appendPlainText("  " + line)
            self.status.setText("Dry run complete. Nothing was changed on this system.")

        def closeEvent(self, event):
            AUDIT.listeners.remove(self._listener)
            if self.worker and self.worker.isRunning():
                self.worker.wait(5000)  # leave no thread or child process behind
            event.accept()

    app = QtWidgets.QApplication(sys.argv[:1])
    app.setStyle("Fusion")
    app.setStyleSheet(STYLE)
    win = Window()
    win.show()
    if shot:  # automated walkthrough used to test the GUI headlessly
        def wait():
            while win.worker and win.worker.isRunning():
                app.processEvents()
            app.processEvents()
        win.do_scan(); wait()
        if win.btn_verify.isEnabled():
            win.do_verify(); wait()
        if win.btn_apply.isEnabled():
            win.do_apply()
        app.processEvents()
        win.grab().save(shot)
        win.close()
        return 0
    return app.exec()


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def print_devices(devices: list[Device]) -> None:
    print(f"{'DEVICE':<58} {'DRIVER':<14} {'VERSION':<26} ID")
    for d in devices:
        print(f"{d.name[:57]:<58} {d.driver[:13]:<14} {d.driver_version[:25]:<26} "
              f"{d.hardware_ids[0] if d.hardware_ids else '-'}")
        for note in d.notes:
            print(f"    note: {note}")


def print_updates(updates: list[Update]) -> None:
    if not updates:
        print("No updates offered.")
    for u in updates:
        print(f"- {u.name}\n    {u.installed} -> {u.available}   [{u.source}]\n    sha256 {u.sha256 or '-'}\n"
              f"    {u.status}{': ' + u.detail if u.detail else ''}")


def main() -> int:
    global AUDIT
    ap = argparse.ArgumentParser(description=f"{APP} {VERSION} (proof of concept; never installs anything)")
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--scan", action="store_true", help="list hardware and installed driver versions")
    mode.add_argument("--dry-run", action="store_true", help="scan and list updates; download nothing")
    mode.add_argument("--update-all", action="store_true", help="scan, download and verify all; print the install plan")
    mode.add_argument("--gui", action="store_true", help="open the GUI")
    mode.add_argument("--self-test", action="store_true", help="test the verification pipeline")
    mode.add_argument("--verify-log", action="store_true", help="check the audit log hash chain")
    ap.add_argument("--manifest", help="path to manifest.json")
    ap.add_argument("--sig", help="path to the detached signature (base64 Ed25519)")
    ap.add_argument("--pubkey", help="hex Ed25519 public key. PoC only: production pins this in the binary")
    ap.add_argument("--gpg-keyring", type=Path, help="pinned keyring for GPG-signed packages")
    ap.add_argument("--demo", action="store_true", help="fake local manifest incl. one tampered package")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--log", type=Path, default=state_dir() / "audit.jsonl", help="audit log path")
    ap.add_argument("--screenshot", help=argparse.SUPPRESS)
    args = ap.parse_args()

    if args.verify_log:
        ok, msg = AuditLog.verify_chain(args.log)
        print(f"{args.log}: {msg}")
        return 0 if ok else 1
    AUDIT = AuditLog(args.log)
    AUDIT.write("session.start", version=VERSION, mode=next(k for k in ("scan", "dry_run", "update_all", "gui",
                "self_test") if getattr(args, k)), os=platform.platform())
    try:
        if args.self_test:
            return self_test()
        ctx = Context(gpg_keyring=args.gpg_keyring, demo=args.demo)
        if args.manifest:
            if not (args.sig and args.pubkey):
                ap.error("--manifest requires --sig and --pubkey: unsigned manifests are never accepted")
            ctx.manifest = load_manifest(Path(args.manifest).read_bytes(), Path(args.sig).read_bytes(), args.pubkey)
        with tempfile.TemporaryDirectory(prefix="safedriver-demo-") as tmp:
            if args.gui:
                return run_gui(ctx, Path(tmp), args.screenshot)
            devices, upgrades = scan()
            if args.demo:
                ctx = build_demo(devices, Path(tmp))
            if args.scan:
                print(json.dumps([dataclasses.asdict(d) for d in devices], indent=1)) if args.json else print_devices(devices)
                return 0
            updates = find_updates(devices, ctx.manifest, upgrades)
            if args.update_all:
                for u in updates:
                    verify_update(u, ctx)
            if args.json:
                print(json.dumps([{**dataclasses.asdict(u), "package": u.package and u.package["id"]} for u in updates], indent=1))
            else:
                print_updates(updates)
                if args.update_all:
                    print("\nInstall plan (NOT executed by the PoC):")
                    print("\n".join("  " + line for line in install_plan(updates)))
            return 1 if any(u.status == "failed" for u in updates) else 0
    except VerificationError as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 2
    finally:
        AUDIT.write("session.end")


if __name__ == "__main__":
    sys.exit(main())
