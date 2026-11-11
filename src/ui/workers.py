"""Background work, so the window never freezes during scans, downloads or installs."""
from __future__ import annotations

from PySide6.QtCore import QThread, Signal


class Worker(QThread):
    """Runs fn(report) on a thread.

    `report(obj)` may be called from fn any number of times and arrives on the GUI thread as
    `progress`. The return value (or the exception raised) arrives as `done`."""
    progress = Signal(object)
    done = Signal(object)

    def __init__(self, fn, parent=None):
        super().__init__(parent)
        self.fn = fn

    def run(self):
        try:
            self.done.emit(self.fn(self.progress.emit))
        except Exception as exc:          # shown in the status line, never swallowed
            self.done.emit(exc)
