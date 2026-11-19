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
            self.done.emit(self.fn(self.report))
        except Exception as exc:          # shown in the status line, never swallowed
            self.done.emit(exc)

    def report(self, message) -> None:
        self.progress.emit(message)


class ScanWorker(Worker):
    """A scan in two observable stages, each event arriving on the GUI thread:

      Stage 1  devices_enumerated(devices)          every local device, right after enumeration
      Stage 2  device_started(device)               a device's own online lookup begins
               device_updated(device, updates)      its result is final ([] = no newer driver)
               update_verifying(update, n, total)   download + verification of one update starts
               update_verified(update, n, total)    ... and has finished (its checks are filled in)
      Always   scan_progress(text, done, total)     total 0 = indeterminate (one search for the whole PC)

    fn(report) sends tuples whose first item names the signal; anything else goes to `progress`."""
    devices_enumerated = Signal(object)
    device_started = Signal(object)
    device_updated = Signal(object, object)
    update_verifying = Signal(object, int, int)
    update_verified = Signal(object, int, int)
    scan_progress = Signal(str, int, int)

    SIGNALS = ("devices_enumerated", "device_started", "device_updated", "update_verifying",
               "update_verified", "scan_progress")

    def report(self, message) -> None:
        if isinstance(message, tuple) and message and message[0] in self.SIGNALS:
            getattr(self, message[0]).emit(*message[1:])
        else:
            self.progress.emit(message)
