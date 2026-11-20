# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for the Windows release (driven by tools/build_windows.py).

One folder, one program:
  DriverInstaller.exe   windowed (no console flash): no arguments opens the GUI; CLI arguments
                        run the CLI on the caller's console; --apply-plan <plan> is the elevated
                        helper, which imports only core/ (see src/windows_main.py).
  _internal/            Python runtime, PySide6, fonts and licences

tools/build_windows.py passes the staged source directory and the version-resource file through
environment variables; the spec itself contains no version or path assumptions.
"""
import os

from PyInstaller.utils.hooks import collect_submodules

SRC = os.environ["DI_STAGED_SRC"]                  # staged copy of src/ with the version stamped in
VERSION_FILE = os.environ.get("DI_VERSION_FILE") or None
ICON = os.environ.get("DI_ICON") or None
NAME = "DriverInstaller"

fonts = os.path.join("ui", "assets", "fonts")
datas = [
    (os.path.join(SRC, fonts, "VT323-Regular.ttf"), fonts),
    (os.path.join(SRC, fonts, "VT323-OFL.txt"), fonts),
    (os.path.join(SRC, "ui", "assets", "icons"), os.path.join("ui", "assets", "icons")),   # checkbox ticks (Clean)
    (os.path.join(SRC, "LICENSE"), "licenses"),
    (os.path.join(SRC, fonts, "VT323-OFL.txt"), "licenses"),
]
hidden = collect_submodules("core") + collect_submodules("ui") + ["cli", "gui", "demo", "helper_main"]
# Never bundled: unused GUI toolkits, Qt modules nothing uses, and test machinery.
excludes = ["tkinter", "unittest", "pydoc_data", "test", "pytest",
            "PySide6.QtQml", "PySide6.QtQuick", "PySide6.QtQuickWidgets", "PySide6.QtPdf", "PySide6.QtNetwork",
            "PySide6.QtOpenGL", "PySide6.QtDBus", "PySide6.QtDesigner", "PySide6.QtHelp", "PySide6.QtUiTools"]

a = Analysis([os.path.join(SRC, "windows_main.py")], pathex=[SRC], datas=datas, hiddenimports=hidden,
             excludes=excludes, noarchive=False)

# exclude_binaries=True + COLLECT = one-folder build: nothing is unpacked to %TEMP% at start-up
# (the one-file mode that antivirus heuristics dislike is not used).
# console=False: a GUI-subsystem program, so Explorer opens no console window.
# uac_admin=False keeps requestedExecutionLevel="asInvoker": the program starts with the user's
# own rights and elevates only itself, with --apply-plan, on demand through UAC.
exe = EXE(PYZ(a.pure), a.scripts, [], exclude_binaries=True, name=NAME, console=False,
          icon=ICON, version=VERSION_FILE, upx=False, disable_windowed_traceback=False,
          uac_admin=False, uac_uiaccess=False)

coll = COLLECT(exe, a.binaries, a.datas, upx=False, name=NAME)
