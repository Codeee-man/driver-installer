"""Driver Installer GUI (PySide6).

Layout: a centred title, one table of devices (Device / Status / Verification / select),
and a bottom bar with "Select all fully checked" and "Download and Install".

Modules
  theme.py         the Matrix look: accent colour and font presets, fonts, stylesheet
  settings.py      remembered preferences (accent, font, update check) in ui.json
  settings_dialog.py  the [ SETTINGS ] dialog
  verification.py  no Qt: Full / Partial / None from an update's check records, and the texts
  models.py        DriverTableModel: rows, selection, "select all fully checked"
  delegates.py     painted badges, the (?) help target, two-line device cell, centred checkbox
  popover.py       ChecksPopover: the itemised check list behind (?)
  workers.py       background thread for scan / verify / install
  dialogs.py       the confirmation dialogs
  main_window.py   the window and the scan -> verify -> install flow

This package imports Qt lazily, so `ui.verification` can be used without PySide6 (the CLI does).
"""
from __future__ import annotations


def create(ctx, workdir, autoscan: bool = False):
    """Build the application and main window with the remembered accent and font; returns
    (app, window)."""
    from .main_window import create as _create
    return _create(ctx, workdir, autoscan=autoscan)


def run(ctx, workdir, shot: str | None = None) -> int:
    """Open the window, start scanning straight away (and, when enabled in Settings, the
    background check for a newer release), and run the event loop."""
    from .main_window import run as _run
    return _run(ctx, workdir, shot)


def settle(app, win, timeout: float = 60.0) -> None:
    """Process events until the window's background work has finished (tests, screenshots)."""
    from .main_window import settle as _settle
    _settle(app, win, timeout)
