# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for the Windows release (driven by tools/build_windows.py).

One folder, three programs sharing one set of libraries:
  driver-installer.exe         console: the CLI (scan / check / update / gui)
  driver-installer-gui.exe     windowed: opens the GUI directly (Start menu / double-click)
  driver-installer-helper.exe  windowed: the elevated helper; accepts only --apply-plan <plan>.
                               Built without Qt so the code that runs as Administrator stays small.

tools/build_windows.py passes the staged source directory and the version-resource file through
environment variables; the spec itself contains no version or path assumptions.
"""
import os

from PyInstaller.utils.hooks import collect_submodules

SRC = os.environ["DI_STAGED_SRC"]                  # staged copy of src/ with the version stamped in
VERSION_FILE = os.environ.get("DI_VERSION_FILE") or None
ICON = os.environ.get("DI_ICON") or None

datas = [
    (os.path.join(SRC, "ui", "assets", "fonts", "VT323-Regular.ttf"), os.path.join("ui", "assets", "fonts")),
    (os.path.join(SRC, "ui", "assets", "fonts", "VT323-OFL.txt"), os.path.join("ui", "assets", "fonts")),
]
app_modules = collect_submodules("core") + collect_submodules("ui") + ["gui", "demo"]
# Never bundled anywhere: unused GUI toolkits and test machinery.
common_excludes = ["tkinter", "unittest", "pydoc_data", "test", "pytest"]
qt_unused = ["PySide6.QtQml", "PySide6.QtQuick", "PySide6.QtQuickWidgets", "PySide6.QtPdf", "PySide6.QtNetwork",
             "PySide6.QtOpenGL", "PySide6.QtDBus", "PySide6.QtDesigner", "PySide6.QtHelp", "PySide6.QtUiTools"]


def analysis(script, hidden, excludes, with_data):
    return Analysis([os.path.join(SRC, script)], pathex=[SRC], datas=datas if with_data else [],
                    hiddenimports=hidden, excludes=common_excludes + excludes, noarchive=False)


cli_a = analysis("cli.py", app_modules, qt_unused, True)
gui_a = analysis("launch_gui.py", app_modules, qt_unused, True)
helper_a = analysis("helper_main.py", collect_submodules("core"), ["PySide6", "shiboken6", "ui", "gui", "demo"], False)


def exe(a, name, console):
    return EXE(PYZ(a.pure), a.scripts, [], exclude_binaries=True, name=name, console=console,
               icon=ICON, version=VERSION_FILE, upx=False, disable_windowed_traceback=False)


cli_exe = exe(cli_a, "driver-installer", True)
gui_exe = exe(gui_a, "driver-installer-gui", False)
helper_exe = exe(helper_a, "driver-installer-helper", False)

coll = COLLECT(cli_exe, gui_exe, helper_exe,
               cli_a.binaries, cli_a.datas, gui_a.binaries, gui_a.datas, helper_a.binaries, helper_a.datas,
               upx=False, name="driver-installer")
