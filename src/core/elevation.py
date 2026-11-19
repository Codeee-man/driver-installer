"""Administrator check, which helper to elevate, and one-shot elevation (UAC on Windows,
pkexec or sudo on Linux).

The GUI and CLI never run elevated. When the user confirms an install, the front end starts
the helper once, elevated, with `--apply-plan`, waits for it and reads its result file. The
elevated process exits when the plan is done; nothing stays resident.

What is elevated, in order of preference (helper_command):
  1. an installed copy that only administrators can change (DriverInstaller-Setup.exe,
     the .deb, tools/install_helper.sh|.ps1)
  2. otherwise this copy of the program, with a warning: DriverInstaller.exe itself on
     Windows, the AppImage, a frozen Linux build, or src/helper_main.py from a checkout
"""
from __future__ import annotations

import ctypes
import logging
import ntpath
import os
import subprocess
import sys
from pathlib import Path

from . import common
from .common import ElevationError

SEE_MASK_NOCLOSEPROCESS, SEE_MASK_NOASYNC, SEE_MASK_FLAG_NO_UI = 0x40, 0x100, 0x400
SW_HIDE, ERROR_CANCELLED, INFINITE = 0, 1223, 0xFFFFFFFF


# ------------------------------------------------------- which helper
# Where an installed, root/Administrators-only helper may live, in order of preference.
HELPER_LINUX = "/usr/local/bin/driver-installer-helper"                  # tools/install_helper.sh
HELPER_LINUX_PACKAGED = "/usr/libexec/driver-installer/driver-installer-helper"   # the .deb package
# Under %ProgramFiles%: DriverInstaller-Setup.exe, then tools/install_helper.ps1 from a checkout.
# On Windows the helper is DriverInstaller.exe itself, started with --apply-plan.
HELPER_WINDOWS = (("Driver Installer", "DriverInstaller.exe"), ("driver-installer", "helper.exe"))
HELPER_FROZEN_NAME = "driver-installer-helper"                            # next to a Linux PyInstaller build
REPO_HELPER = Path(__file__).resolve().parents[1] / "helper_main.py"
log = logging.getLogger("safedriver")


def _admin_only(path: str) -> bool:
    """True if only root can modify `path` (owner root, not group- or world-writable)."""
    st = os.stat(path)
    return st.st_uid == 0 and not st.st_mode & 0o022


def _program_files() -> str:
    return os.environ.get("ProgramFiles", r"C:\Program Files")


def installed_helper() -> str | None:
    """The system-installed elevated helper (install_helper.sh / .ps1, or the .deb), or None.

    On Linux the helper and its directory must be writable by root only; a helper that
    fails this is never used and never silently replaced by another copy."""
    if common.OS_NAME == "windows":
        for folder, name in HELPER_WINDOWS:
            path = ntpath.join(_program_files(), folder, name)
            if os.path.isfile(path):
                return path
        return None
    for candidate in (HELPER_LINUX, HELPER_LINUX_PACKAGED):
        if not os.path.isfile(candidate):
            continue
        for part in (candidate, os.path.dirname(candidate)):
            if not _admin_only(part):
                raise ElevationError(f"{part} can be modified by non-administrators; refusing to elevate it. "
                                     "Reinstall the package, or run tools/install_helper.sh")
        return candidate
    return None


def _unprotected_helper() -> tuple[list[str], str]:
    """(command prefix, description) for a helper that is NOT in a protected location."""
    if getattr(sys, "frozen", False) and common.OS_NAME == "windows":
        # DriverInstaller.exe is GUI, CLI and helper in one: it elevates itself (portable copy).
        return [str(Path(sys.executable).resolve())], str(Path(sys.executable).resolve())
    if getattr(sys, "frozen", False):                    # Linux PyInstaller build
        helper = Path(sys.executable).resolve().parent / HELPER_FROZEN_NAME
        if not helper.is_file():
            raise ElevationError(f"{HELPER_FROZEN_NAME} is missing next to {Path(sys.executable).name}; "
                                 "reinstall the application")
        return [str(helper)], str(helper)
    appimage = os.environ.get("APPIMAGE")
    if appimage and os.path.isfile(appimage) and common.OS_NAME == "linux":
        # The AppImage's own mount is not visible to root, so elevate the AppImage file itself;
        # its AppRun starts the helper when the first argument is --apply-plan. The runtime flag
        # avoids needing FUSE as root (pkexec drops APPIMAGE_EXTRACT_AND_RUN from the environment).
        return [appimage, "--appimage-extract-and-run"], appimage
    # -I: isolated mode, so the elevated interpreter ignores PYTHON* variables and the user's site dir.
    return [sys.executable, "-I", str(REPO_HELPER)], str(REPO_HELPER)


def helper_command(plan_path) -> list[str]:
    """Command line of the elevated helper for a plan. Prefers the system-installed helper;
    otherwise uses the one shipped with this copy of the program, with a warning."""
    helper = installed_helper()
    if helper:
        return [helper, "--apply-plan", str(plan_path)]
    prefix, where = _unprotected_helper()
    if common.OS_NAME == "windows":
        fix = "install it with DriverInstaller-Setup.exe, which puts it in Program Files"
    else:
        fix = "install the .deb package or run tools/install_helper.sh"
    log.warning(f"running un-installed: elevating {where}, which ordinary users may be able to modify; {fix}")
    common.audit("elevation.warning", reason="helper not installed", helper=where)
    return [*prefix, "--apply-plan", str(plan_path)]


# ------------------------------------------------------------- running


class SHELLEXECUTEINFOW(ctypes.Structure):
    """Fixed-width field types so the layout is identical wherever it is built (112 bytes on x64)."""
    _fields_ = [
        ("cbSize", ctypes.c_uint32), ("fMask", ctypes.c_uint32), ("hwnd", ctypes.c_void_p),
        ("lpVerb", ctypes.c_wchar_p), ("lpFile", ctypes.c_wchar_p), ("lpParameters", ctypes.c_wchar_p),
        ("lpDirectory", ctypes.c_wchar_p), ("nShow", ctypes.c_int32), ("hInstApp", ctypes.c_void_p),
        ("lpIDList", ctypes.c_void_p), ("lpClass", ctypes.c_wchar_p), ("hkeyClass", ctypes.c_void_p),
        ("dwHotKey", ctypes.c_uint32), ("hIconOrMonitor", ctypes.c_void_p), ("hProcess", ctypes.c_void_p),
    ]


def is_admin() -> bool:
    if common.OS_NAME == "windows":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (AttributeError, OSError):
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


def method() -> str | None:
    """How elevation would be requested here, or None if there is no way to ask."""
    if common.OS_NAME == "windows":
        return "uac"
    if common.have("pkexec") and (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")
                                  or sys.stdin.isatty()):
        return "pkexec"
    if common.have("sudo") and sys.stdin.isatty():
        return "sudo"
    return None


def _run_uac(argv: list[str], timeout: int | None) -> int:
    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    shell32.ShellExecuteExW.argtypes = [ctypes.POINTER(SHELLEXECUTEINFOW)]
    shell32.ShellExecuteExW.restype = ctypes.c_int32
    kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    kernel32.WaitForSingleObject.restype = ctypes.c_uint32
    kernel32.GetExitCodeProcess.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
    kernel32.GetExitCodeProcess.restype = ctypes.c_int32
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]

    info = SHELLEXECUTEINFOW()
    info.cbSize = ctypes.sizeof(info)
    info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI
    info.lpVerb = "runas"                                   # triggers the UAC consent prompt
    info.lpFile = argv[0]
    info.lpParameters = subprocess.list2cmdline(argv[1:])
    info.nShow = SW_HIDE
    if not shell32.ShellExecuteExW(ctypes.byref(info)):
        err = ctypes.get_last_error()
        if err == ERROR_CANCELLED:
            raise ElevationError("the UAC prompt was declined")
        raise ElevationError(f"could not start the elevated helper (Windows error {err})")
    try:
        kernel32.WaitForSingleObject(info.hProcess, INFINITE if timeout is None else timeout * 1000)
        code = ctypes.c_uint32(1)
        kernel32.GetExitCodeProcess(info.hProcess, ctypes.byref(code))
        return code.value
    finally:
        kernel32.CloseHandle(info.hProcess)


def _run_posix(argv: list[str], how: str, timeout: int | None) -> int:
    prefix = [common.resolve_binary("pkexec")] if how == "pkexec" else [common.resolve_binary("sudo"), "--"]
    try:
        proc = subprocess.run(prefix + argv, timeout=timeout, stdout=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ElevationError(f"could not run the elevated helper: {exc}") from exc
    if how == "pkexec" and proc.returncode in (126, 127):
        raise ElevationError("authorisation was declined or failed")
    return proc.returncode


def run_elevated(argv: list[str], timeout: int | None = None) -> int:
    """Run argv with administrator rights, wait, return its exit code.
    Raises ElevationError if the user declines or no elevation mechanism exists."""
    how = method()
    common.audit("elevation.request", method=how, program=argv[0], args=argv[1:])
    if how is None:
        raise ElevationError("administrator rights are required and neither pkexec nor sudo is usable here; "
                             "re-run from an administrator shell")
    code = _run_uac(argv, timeout) if how == "uac" else _run_posix(argv, how, timeout)
    common.audit("elevation.finished", method=how, rc=code)
    return code
