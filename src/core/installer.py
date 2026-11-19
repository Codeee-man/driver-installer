"""Platform execution engine: pnputil (Windows), fwupd and native package managers (Linux).

`dry_run=True` is the default everywhere in this module. A real run refuses to
start unless the process is already elevated; requesting elevation is the job
of engine.apply(), not of this module.
"""
from __future__ import annotations

import dataclasses
import ntpath
import os
import re
import stat
import zipfile
from pathlib import Path

from . import common, elevation, verifier
from .security import loldrivers
from .common import ElevationError, InstallError

MAX_EXTRACT_BYTES = 4 << 30
ERROR_SUCCESS_REBOOT_REQUIRED, ERROR_NO_MORE_ITEMS = 3010, 259
PACKAGE_MANAGERS = ("apt-get", "dnf", "pacman", "zypper")
_LOCAL_FORMATS = {"apt-get": "deb", "dnf": "rpm", "zypper": "rpm", "pacman": "pkg"}


@dataclasses.dataclass
class InstallResult:
    package_id: str
    status: str                 # installed | reboot-required | no-op | failed | dry-run
    rc: int = 0
    detail: str = ""
    commands: list[list[str]] = dataclasses.field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.status in ("installed", "reboot-required", "no-op")


def detect_package_manager() -> str | None:
    return next((pm for pm in PACKAGE_MANAGERS if common.have(pm)), None)


def package_manager_command(pm: str, *, package_name: str | None = None, local_file: str | None = None) -> list[str]:
    """Non-interactive install command. Repository installs are verified by the package
    manager against the distro's own keys; local files were verified by verifier.py first."""
    if local_file:
        target = [local_file if os.path.isabs(local_file) else "./" + local_file]
        return {"apt-get": ["apt-get", "install", "-y", "--no-install-recommends", *target],
                "dnf": ["dnf", "install", "-y", *target],
                "zypper": ["zypper", "--non-interactive", "install", *target],
                "pacman": ["pacman", "-U", "--noconfirm", *target]}[pm]
    target = ["--", package_name]
    return {"apt-get": ["apt-get", "install", "-y", "--no-install-recommends", *target],
            "dnf": ["dnf", "install", "-y", *target],
            "zypper": ["zypper", "--non-interactive", "install", *target],
            "pacman": ["pacman", "-S", "--noconfirm", "--needed", *target],
            "mhwd": ["mhwd", "-i", "pci", package_name]}[pm]        # Manjaro hardware configs


def build_commands(pkg: dict, path: str, extract_dir: str, pm: str | None = None) -> list[list[str]]:
    """The external commands an install runs, in order. Pure: used for dry runs and real runs alike."""
    inst, art = pkg["install"], pkg.get("artifact")
    method = inst["method"]
    if method == "pnputil":
        cmds = [["expand", "-F:*", path, extract_dir]] if art["format"] == "cab" else []
        if inst.get("inf_path"):
            cmds.append(["pnputil", "/add-driver", ntpath.join(extract_dir, inst["inf_path"]), "/install"])
        else:
            cmds.append(["pnputil", "/add-driver", ntpath.join(extract_dir, "*.inf"), "/subdirs", "/install"])
        return cmds
    if method == "fwupd":
        return [["fwupdmgr", "install", path, "--assume-yes", "--no-reboot-check"]]
    pm = inst.get("manager") or pm or detect_package_manager()
    if not pm:
        return [["<package-manager>", "install", path if art else inst["package_name"]]]
    if art:
        if art["format"] != _LOCAL_FORMATS.get(pm):
            raise InstallError(f"{pkg['id']}: a .{art['format']} package cannot be installed with {pm}")
        return [package_manager_command(pm, local_file=path)]
    return [package_manager_command(pm, package_name=inst["package_name"])]


def fwupd_device_command(device_id: str) -> list[str]:
    if not re.fullmatch(r"[0-9a-f]{40}", device_id):
        raise InstallError("fwupd device id is malformed")
    return ["fwupdmgr", "update", device_id, "--assume-yes", "--no-reboot-check"]


def safe_extract_zip(archive: Path, dest: Path) -> list[Path]:
    """Extract a zip, refusing absolute paths, '..', symlinks and oversized contents."""
    dest = Path(dest).resolve()
    out, total = [], 0
    with zipfile.ZipFile(archive) as zf:
        for info in zf.infolist():
            name = info.filename.replace("\\", "/")
            target = (dest / name).resolve()
            if name.startswith("/") or re.match(r"^[A-Za-z]:", name) or ".." in name.split("/") \
                    or (target != dest and dest not in target.parents):
                raise InstallError(f"archive member escapes the extraction directory: {info.filename!r}")
            if stat.S_ISLNK(info.external_attr >> 16):
                raise InstallError(f"archive contains a symbolic link: {info.filename!r}")
            total += info.file_size
            if total > MAX_EXTRACT_BYTES:
                raise InstallError("archive expands beyond the size limit")
        for info in zf.infolist():
            out.append(Path(zf.extract(info, dest)))
    return out


def _execute(cmd: list[str], env: dict | None = None) -> common.Result:
    res = common.run(cmd, timeout=3600, env=env)
    if res is None:
        raise InstallError(f"{cmd[0]} is not available on this system")
    return res


def _tail(res: common.Result) -> str:
    lines = [ln for ln in (res.stdout + "\n" + res.stderr).splitlines() if ln.strip()]
    return " | ".join(lines[-3:])[:400]


def unpack_package(path: Path, fmt: str, dest: Path) -> None:
    """Unpack a driver package into `dest`: .zip with path-traversal and size checks, .cab with
    Windows' expand.exe. The one unpacker used both before the user decides (engine) and in the
    elevated helper. Raises InstallError."""
    if fmt == "zip":
        try:
            safe_extract_zip(path, dest)
        except (OSError, zipfile.BadZipFile) as exc:
            raise InstallError(f"the driver package could not be unpacked safely: {exc}") from exc
    elif fmt == "cab":
        if common.OS_NAME != "windows":
            raise InstallError("a .cab driver package can only be unpacked on Windows")
        res = _execute(["expand", "-F:*", str(path), str(dest)])
        if res.rc != 0:
            raise InstallError("could not unpack the cabinet: " + _tail(res))
    else:
        raise InstallError(f"pnputil needs a .cab or .zip driver package, not .{fmt}")


def _prepare_pnputil(pkg: dict, path: Path, workdir: Path, blocklist=None) -> list[str]:
    """Unpack, run the LOLDrivers check on every .sys, check the catalog signer and locate
    the .inf. Changes nothing outside `workdir`. Raises loldrivers.SecurityAlert on a hit."""
    art, inst = pkg["artifact"], pkg["install"]
    extract_dir = Path(workdir) / ("extract-" + re.sub(r"[^a-z0-9]", "_", pkg["id"]))
    extract_dir.mkdir(parents=True, exist_ok=False)
    unpack_package(path, art["format"], extract_dir)
    if blocklist is not None:
        loldrivers.check_directory(extract_dir, blocklist)       # BYOVD gate, before anything else
    sig = art["signature"]
    if sig["type"] == "authenticode" and sig.get("target", "artifact") == "catalog":
        verifier.verify_catalogs(extract_dir, sig["subject"], sig.get("certificate_thumbprint"))
    if inst.get("inf_path"):
        inf = (extract_dir / inst["inf_path"].replace("\\", "/")).resolve()
        if extract_dir.resolve() not in inf.parents or not inf.is_file():
            raise InstallError(f"{pkg['id']}: {inst['inf_path']} is not in the driver package")
        return ["pnputil", "/add-driver", str(inf), "/install"]
    if not list(extract_dir.rglob("*.inf")):
        raise InstallError(f"{pkg['id']}: the driver package contains no .inf file")
    return ["pnputil", "/add-driver", str(extract_dir / "*.inf"), "/subdirs", "/install"]


def prepare(pkg: dict, path: Path | None, workdir: Path | None, blocklist=None) -> list[str]:
    """Do everything that can fail without touching the system (unpack, LOLDrivers check,
    catalog signature, locate the .inf, find the package manager) and return the one command
    that installs. The helper calls this for every package BEFORE it takes the restore point.
    `blocklist` is a loldrivers.Blocklist; None skips the check (the caller decided that)."""
    if not elevation.is_admin():
        raise ElevationError("installing drivers requires administrator rights")
    method = pkg["install"]["method"]
    if method == "pnputil":
        if common.OS_NAME != "windows":
            raise InstallError("pnputil packages can only be installed on Windows")
        return _prepare_pnputil(pkg, Path(path), Path(workdir), blocklist)
    if method == "fwupd":
        if not common.have("fwupdmgr"):
            raise InstallError("fwupdmgr is not available on this system")
        return build_commands(pkg, str(path), "")[0]
    pm = pkg["install"].get("manager") or detect_package_manager()
    if not pm or not common.have(pm):
        raise InstallError("no supported package manager found (apt, dnf, pacman, zypper)")
    return build_commands(pkg, str(path) if path else "", "", pm)[0]


def execute(pkg: dict, cmd: list[str]) -> InstallResult:
    """Run the install command produced by prepare() and interpret its exit code."""
    if not elevation.is_admin():
        raise ElevationError("installing drivers requires administrator rights")
    common.audit("install.start", package=pkg["id"], version=pkg["version"], method=pkg["install"]["method"])
    pid, reboot = pkg["id"], bool(pkg["install"].get("reboot_required"))
    try:
        res = _execute(cmd, {"DEBIAN_FRONTEND": "noninteractive"} if cmd[0] == "apt-get" else None)
        if res.rc == 0:
            result = InstallResult(pid, "reboot-required" if reboot else "installed", 0,
                                   "installed; restart to finish" if reboot else "installed", [cmd])
        elif cmd[0] == "pnputil" and res.rc == ERROR_SUCCESS_REBOOT_REQUIRED:
            result = InstallResult(pid, "reboot-required", res.rc, "driver installed; restart to finish", [cmd])
        elif cmd[0] == "pnputil" and res.rc == ERROR_NO_MORE_ITEMS:
            result = InstallResult(pid, "no-op", res.rc,
                                   "driver added to the store; no device needed it (already up to date)", [cmd])
        elif cmd[0] == "fwupdmgr" and res.rc == 2:
            result = InstallResult(pid, "no-op", 2, "fwupd reports nothing to do", [cmd])
        else:
            result = InstallResult(pid, "failed", res.rc, _tail(res), [cmd])
        if result.ok and pkg["install"]["method"] == "package-manager" and common.have("dkms"):
            dk = common.run(["dkms", "status"])
            if dk and dk.rc == 0 and dk.stdout.strip():
                result.detail += "; DKMS: " + " / ".join(dk.stdout.strip().splitlines()[:3])
    except InstallError as exc:
        result = InstallResult(pid, "failed", -1, str(exc))
    common.audit("install.result", **dataclasses.asdict(result))
    return result


def install(pkg: dict, path: Path | None, *, dry_run: bool = True, workdir: Path | None = None,
            blocklist=None) -> InstallResult:
    """Install one verified package. `path` is the helper's private, hash-verified copy
    (None for a repository package). Dry run unless told otherwise."""
    if dry_run:
        cmds = build_commands(pkg, str(path) if path else "<verified-file>", "<extract-dir>")
        return InstallResult(pkg["id"], "dry-run", 0, "nothing was changed", cmds)
    if not elevation.is_admin():
        raise ElevationError("installing drivers requires administrator rights")
    try:
        cmd = prepare(pkg, path, workdir, blocklist)
    except loldrivers.SecurityAlert:
        raise                                   # never downgraded to an ordinary failure
    except (InstallError, common.VerificationError) as exc:
        result = InstallResult(pkg["id"], "failed", -1, str(exc))
        common.audit("install.result", **dataclasses.asdict(result))
        return result
    return execute(pkg, cmd)


def install_fwupd_device(device_id: str, *, dry_run: bool = True) -> InstallResult:
    """Apply an update fwupd itself found on LVFS (fwupd downloads and verifies it)."""
    cmd = fwupd_device_command(device_id)
    if dry_run:
        return InstallResult(f"fwupd:{device_id}", "dry-run", 0, "nothing was changed", [cmd])
    if not elevation.is_admin():
        raise ElevationError("flashing firmware requires administrator rights")
    res = _execute(cmd)
    status = "installed" if res.rc == 0 else "no-op" if res.rc == 2 else "failed"
    result = InstallResult(f"fwupd:{device_id}", status, res.rc,
                           "firmware update accepted by fwupd; a restart may be needed to finish"
                           if res.rc == 0 else _tail(res), [cmd])
    common.audit("install.result", **dataclasses.asdict(result))
    return result
