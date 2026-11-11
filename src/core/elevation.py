"""Administrator check and one-shot elevation (UAC on Windows, pkexec or sudo on Linux).

The GUI and CLI never run elevated. When the user confirms an install, the
front end starts this same program once more, elevated, with `--apply-plan`,
waits for it and reads its result file. The elevated process exits when the
plan is done; nothing stays resident.
"""
from __future__ import annotations

import ctypes
import os
import subprocess
import sys

from . import common
from .common import ElevationError

SEE_MASK_NOCLOSEPROCESS, SEE_MASK_NOASYNC, SEE_MASK_FLAG_NO_UI = 0x40, 0x100, 0x400
SW_HIDE, ERROR_CANCELLED, INFINITE = 0, 1223, 0xFFFFFFFF


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
