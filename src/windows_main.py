"""Entry point of DriverInstaller.exe, the single Windows program (GUI, CLI and elevated helper).

It is built as a windowed program (no console subsystem), so double-clicking it opens the GUI
without a console window flashing up. What it does depends on the command line:

    DriverInstaller.exe                          the GUI
    DriverInstaller.exe --apply-plan <plan>      the elevated helper (started by itself through UAC)
    DriverInstaller.exe <anything else>          the CLI: scan, check, update, gui, --help, ...

For the CLI, a windowed program has no console of its own. Output that was redirected (a pipe or
file, e.g. `DriverInstaller.exe scan --json > scan.json`, or the driver-installer.cmd shim under
a script) is used as it is; otherwise the program attaches to the console of the shell that
started it and writes there. cmd.exe does not wait for a windowed program when you type its name
at the prompt, so for interactive use prefer `driver-installer` (the .cmd shim the installer can
put on PATH), `start /wait DriverInstaller.exe ...`, or PowerShell's `Start-Process -Wait`.

The helper branch imports only core/ (no Qt), the same code as the former separate helper.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

HELPER_FLAG = "--apply-plan"
ATTACH_PARENT_PROCESS = 0xFFFFFFFF            # (DWORD)-1
STD_HANDLES = (("stdin", -10, "CONIN$", "r"), ("stdout", -11, "CONOUT$", "w"), ("stderr", -12, "CONOUT$", "w"))


def _usable(stream) -> bool:
    try:
        return stream is not None and stream.fileno() >= 0
    except (OSError, ValueError, AttributeError):
        return False


def attach_console(kernel32=None, opener=open) -> str:
    """Give a windowed process working stdin/stdout/stderr for CLI use. Returns how:
    'inherited' (every stream was redirected by the caller), 'attached' (parent's console),
    or 'none' (started without a console, e.g. from a shortcut: output is discarded)."""
    if sys.platform != "win32" and kernel32 is None:
        return "inherited"
    import ctypes
    if kernel32 is None:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.GetStdHandle.restype = ctypes.c_void_p
        kernel32.GetStdHandle.argtypes = [ctypes.c_ulong]
        kernel32.GetFileType.argtypes = [ctypes.c_void_p]
        kernel32.AttachConsole.argtypes = [ctypes.c_ulong]
    missing = []
    for name, std, _console, mode in STD_HANDLES:
        if _usable(getattr(sys, name)):
            continue
        # A handle passed by the caller (redirection) that Python did not wrap: use it.
        handle = kernel32.GetStdHandle(std & 0xFFFFFFFF)
        if handle and handle != ctypes.c_void_p(-1).value and kernel32.GetFileType(handle) != 0:
            import msvcrt
            fd = msvcrt.open_osfhandle(handle, os.O_RDONLY if mode == "r" else os.O_WRONLY)
            setattr(sys, name, os.fdopen(fd, mode, encoding="utf-8", errors="replace", buffering=1, closefd=False))
        else:
            missing.append((name, mode))
    if not missing:
        return "inherited"
    how = "attached" if kernel32.AttachConsole(ATTACH_PARENT_PROCESS) else "none"
    for name, mode in missing:
        target = dict((n, c) for n, _s, c, _m in STD_HANDLES)[name] if how == "attached" else os.devnull
        try:
            # open("CONOUT$") gives Python's console I/O (Unicode via WriteConsoleW).
            setattr(sys, name, opener(target, mode, encoding="utf-8", errors="replace", buffering=1))
        except OSError:
            setattr(sys, name, opener(os.devnull, mode))
    if how == "attached" and any(name == "stdout" for name, _ in missing):
        # Output goes to the shell's console, which printed its prompt already: fresh line.
        print(file=sys.stdout)
    return how


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else list(argv)
    if argv[:1] == [HELPER_FLAG]:
        import helper_main                   # core/ only: what runs as Administrator stays small
        return helper_main.main(argv)
    from cli import main as cli_main
    if not argv:
        return cli_main(["gui"])
    attach_console()
    return cli_main(argv)


if __name__ == "__main__":
    sys.exit(main())
