"""The Driver Installer window.

Flow: the window opens -> enumerate hardware (every device appears at once, queued) -> look
each device up online (rows settle one by one: "To update" moves up, the rest become "Up to
date") -> download and verify every update in the background (badges become final) -> the
user ticks rows -> "Download and Install" -> confirmation -> one administrator prompt ->
restore point -> install. The progress bar under the table pulses while nothing can be
counted (enumeration, a whole-PC search, the install) and counts devices or updates otherwise.

The window never runs elevated. Closing it leaves no thread or process behind.
"""
from __future__ import annotations

import functools
import time
from pathlib import Path

from PySide6.QtCore import QModelIndex, Qt
from PySide6.QtWidgets import (QAbstractItemView, QApplication, QCheckBox, QFrame, QGridLayout, QHBoxLayout,
                               QHeaderView, QLabel, QMainWindow, QPlainTextEdit, QProgressBar, QPushButton,
                               QTableView, QVBoxLayout, QWidget)

from core import common, engine
from core.common import ElevationError
from core.model import FAILED
from . import dialogs, settings, theme
from . import verification as vf
from .delegates import BadgeDelegate, CheckDelegate, NameDelegate, Spinner
from .models import COL_DEVICE, COL_SELECT, COL_STATUS, COL_VERIFY, DriverTableModel
from .popover import ChecksPopover
from .workers import ScanWorker, Worker

TITLE = "Driver Installer"


class DriverView(QTableView):
    """Table with keyboard access to the check details: Enter or ? on a row opens them."""

    def __init__(self, open_details, parent=None):
        super().__init__(parent)
        self._open_details = open_details

    def keyPressEvent(self, event):
        if event.key() in (Qt.Key_Return, Qt.Key_Enter, Qt.Key_Question) and self.currentIndex().isValid():
            self._open_details(self.currentIndex().siblingAtColumn(COL_VERIFY))
            return
        if event.key() == Qt.Key_Space and self.currentIndex().isValid():
            index = self.currentIndex().siblingAtColumn(COL_SELECT)
            if index.flags() & Qt.ItemIsUserCheckable:
                checked = index.data(Qt.CheckStateRole) in (Qt.Checked, Qt.Checked.value)
                self.model().setData(index, Qt.Unchecked if checked else Qt.Checked, Qt.CheckStateRole)
            return
        super().keyPressEvent(event)


class MainWindow(QMainWindow):
    def __init__(self, ctx: engine.Context, workdir: Path):
        super().__init__()
        self.ctx, self.workdir = ctx, Path(workdir)
        self.worker: Worker | None = None
        self._jobs = 0                            # background jobs started and not yet handled
        self.popover: ChecksPopover | None = None
        self.overrides = (False, False)          # (no restore point, no LOLDrivers list) agreed by the user
        self.ask = functools.partial(dialogs.ask, self)
        self.setWindowTitle(TITLE)
        self.resize(1000, 640)
        self.setMinimumSize(720, 420)

        root = QWidget(objectName="root")
        self.setCentralWidget(root)
        layout = QVBoxLayout(root)
        layout.setContentsMargins(20, 14, 20, 16)
        layout.setSpacing(12)

        # header: [log]   Driver Installer   [theme] [rescan]
        header = QGridLayout()
        header.setColumnStretch(0, 1)
        header.setColumnStretch(2, 1)
        self.btn_log = QPushButton("LOG", objectName="ghost", checkable=True, toolTip="Show the activity log")
        self.title = QLabel(TITLE, objectName="title", alignment=Qt.AlignCenter)
        self.btn_theme = QPushButton(objectName="ghost")
        self.btn_rescan = QPushButton("RESCAN", objectName="ghost", toolTip="Scan hardware and check for updates again")
        right = QHBoxLayout()
        right.setSpacing(4)
        right.addWidget(self.btn_theme)
        right.addWidget(self.btn_rescan)
        header.addWidget(self.btn_log, 0, 0, Qt.AlignLeft | Qt.AlignVCenter)
        header.addWidget(self.title, 0, 1)
        header.addLayout(right, 0, 2, Qt.AlignRight | Qt.AlignVCenter)
        layout.addLayout(header)
        layout.addWidget(QFrame(objectName="rule"))

        # table
        self.model = DriverTableModel(self)
        self.view = DriverView(self.open_details)
        self.view.setModel(self.model)
        self.view.setMouseTracking(True)
        self.view.setShowGrid(False)
        self.view.setWordWrap(False)
        self.view.setAlternatingRowColors(False)
        self.view.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.view.setSelectionMode(QAbstractItemView.SingleSelection)
        self.view.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.view.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.view.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)
        self.view.verticalHeader().hide()
        hh = self.view.horizontalHeader()
        hh.setHighlightSections(False)
        hh.setSectionResizeMode(COL_DEVICE, QHeaderView.Stretch)
        for col, width in ((COL_STATUS, 190), (COL_VERIFY, 180), (COL_SELECT, 56)):
            hh.setSectionResizeMode(col, QHeaderView.Fixed)
            self.view.setColumnWidth(col, width)
        self.spinner = Spinner(self.view)
        self.badges = BadgeDelegate(self.view, spinner=self.spinner)
        self.view.setItemDelegateForColumn(COL_DEVICE, NameDelegate(self.view))
        self.view.setItemDelegateForColumn(COL_STATUS, self.badges)
        self.view.setItemDelegateForColumn(COL_VERIFY, self.badges)
        self.view.setItemDelegateForColumn(COL_SELECT, CheckDelegate(self.view))
        self.view.setAccessibleName("Devices and driver updates")
        layout.addWidget(self.view, 1)

        self.log = QPlainTextEdit(objectName="log", readOnly=True, maximumBlockCount=800)
        self.log.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.log.setFixedHeight(130)
        self.log.hide()
        layout.addWidget(self.log)

        # bottom bar: status line with the progress bar beside it, then the actions
        self.status = QLabel(objectName="statusline")
        self.status.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.counter = QLabel(objectName="counter")
        self.progress = QProgressBar(objectName="progress", textVisible=False)
        self.progress.setFixedSize(220, 10)
        self.progress.setAccessibleName("Progress")
        status_row = QHBoxLayout()
        status_row.setSpacing(10)
        status_row.addWidget(self.status, 1)
        status_row.addWidget(self.counter)
        status_row.addWidget(self.progress, 0, Qt.AlignVCenter)
        layout.addLayout(status_row)
        self.progress_idle()
        bar = QHBoxLayout()
        bar.setSpacing(12)
        self.select_full = QCheckBox("Select all fully checked", tristate=True)
        self.select_full.setToolTip("Select every update whose verification is Full")
        self.btn_install = QPushButton("Download and Install", objectName="primary")
        self.btn_install.setCursor(Qt.PointingHandCursor)
        bar.addWidget(self.select_full)
        bar.addStretch(1)
        bar.addWidget(self.btn_install)
        layout.addLayout(bar)

        self.btn_log.toggled.connect(self.log.setVisible)
        self.btn_theme.clicked.connect(self.toggle_theme)
        self.btn_rescan.clicked.connect(self.start_scan)
        self.select_full.clicked.connect(self.toggle_full)
        self.btn_install.clicked.connect(lambda: self.do_install())
        self.badges.helpRequested.connect(self.show_popover)
        self.model.selectionChanged.connect(self.update_controls)
        self.model.spinningChanged.connect(self.spinner.set_running)
        self._listener = self._log_record
        common.audit_log().listeners.append(self._listener)
        self.say("Ready.")
        self.apply_theme(theme.current().name, save=False)
        self.update_controls()

    # ------------------------------------------------------------- theme
    def apply_theme(self, name: str, save: bool = True) -> None:
        """Switch theme in place: stylesheet, header font, row height, labels, painted cells."""
        t = theme.set_current(name)
        app = QApplication.instance()
        if app is not None:
            app.setStyleSheet(theme.stylesheet())
        self.view.horizontalHeader().setFont(theme.font(8, bold=True, spacing=1.2 if t.uppercase else None))
        self.view.verticalHeader().setDefaultSectionSize(t.row_height)
        self.btn_log.setText(t.header_labels["log"])
        self.btn_rescan.setText(t.header_labels["rescan"])
        self.btn_theme.setText(t.label)
        other = theme.CLEAN if t.name == theme.MATRIX else theme.MATRIX
        self.btn_theme.setToolTip(f"Theme: {t.name.capitalize()}. Click for {other.capitalize()}.")
        self.btn_theme.setAccessibleName(f"Theme: {t.name}")
        if self.popover is not None:
            try:
                self.popover.close()
            except RuntimeError:
                pass
            self.popover = None
        self.say(*getattr(self, "_said", ("Ready.", "")))     # re-render with this theme's prompt style
        for widget in (self.status, self.title):
            widget.style().unpolish(widget)
            widget.style().polish(widget)
        self.view.viewport().update()
        self.view.horizontalHeader().viewport().update()
        if save:
            settings.save(theme=t.name)

    def toggle_theme(self) -> None:
        self.apply_theme(theme.CLEAN if theme.current().name == theme.MATRIX else theme.MATRIX)

    # ------------------------------------------------------------ helpers
    def _log_record(self, rec: dict) -> None:
        from core import diagnostics
        line = diagnostics.format_record(rec)                 # step-by-step discovery counts and skip reasons
        # audit events can come from worker threads; hand the text to the GUI thread
        from PySide6.QtCore import QMetaObject, Q_ARG
        QMetaObject.invokeMethod(self.log, "appendPlainText", Qt.QueuedConnection, Q_ARG(str, line))

    def say(self, text: str, kind: str = "") -> None:
        self._said = (text, kind)
        self.status.setText(("> " if theme.current().name == theme.MATRIX else "") + text)
        self.status.setProperty("kind", kind)
        self.status.style().unpolish(self.status)
        self.status.style().polish(self.status)

    @property
    def busy(self) -> bool:
        """True from the start of a background job until its result has been handled, so the
        window never looks idle in the gap between a thread ending and its result arriving."""
        return self._jobs > 0

    def run_in_background(self, fn, on_done, on_progress=None, worker: Worker | None = None) -> Worker:
        self._jobs += 1
        self.worker = worker or Worker(fn, self)
        if on_progress:
            self.worker.progress.connect(on_progress)
        self.worker.done.connect(lambda result: self._job_done(on_done, result))
        self.worker.start()
        self.update_controls()
        return self.worker

    def _job_done(self, on_done, result) -> None:
        # Runs on the GUI thread: nothing else can observe the window between these two lines,
        # and a retry started by on_done counts itself before control returns to the event loop.
        self._jobs -= 1
        try:
            on_done(result)
        finally:
            if not self.busy:
                self.progress_idle()
            self.update_controls()

    # ---------------------------------------------------------- progress
    def progress_pulse(self) -> None:
        """Indeterminate: something runs whose length cannot be counted."""
        self.counter.clear()
        self.progress.setRange(0, 0)
        self.progress.show()

    def progress_count(self, done: int, total: int) -> None:
        self.progress.setRange(0, max(total, 1))
        self.progress.setValue(min(done, total))
        self.counter.setText(f"{done} / {total}")
        self.progress.show()

    def progress_idle(self) -> None:
        self.progress.setRange(0, 1)
        self.progress.setValue(0)
        self.progress.hide()
        self.counter.clear()

    def update_controls(self) -> None:
        counts = self.model.counts()
        busy = self.busy
        self.btn_install.setEnabled(counts["selected"] > 0 and not busy)
        self.btn_rescan.setEnabled(not busy)
        self.select_full.setEnabled(counts["full"] > 0 and not busy)
        self.select_full.setCheckState(self.model.full_state())

    def idle_summary(self) -> str:
        c = self.model.counts()
        if not self.model.rows:
            return "No devices found."
        if c["not_checked"]:
            return (f"{c['updates']} update(s) found · {c['not_checked']} of {c['devices']} devices "
                    "could not be checked")
        if c["updates"] == 0:
            return f"{c['devices']} devices · everything is up to date."
        return f"{c['updates']} update(s) found · {c['selected']} selected · {c['devices']} devices"

    def show_notes(self) -> bool:
        if self.ctx.notes:
            self.say("; ".join(self.ctx.notes), "warn")
            self.ctx.notes.clear()
            return True
        return False

    # -------------------------------------------------------------- scan
    def start_scan(self) -> None:
        """Stage 1: enumerate hardware and show every device at once. Stage 2: look each one up
        online and settle its row as soon as its answer is in, then download and verify every
        update. All of it on a ScanWorker; the window only reacts to its signals."""
        if self.busy:
            return
        self.say("Scanning hardware…")
        self.progress_pulse()

        def work(report):
            report(("scan_progress", "Scanning hardware…", 0, 0))
            devices, upgrades = engine.scan()
            if self.ctx.demo and self.ctx.manifest is None:
                import demo
                self.ctx = demo.build(devices, self.workdir)
            report(("devices_enumerated", devices))
            settled: set[int] = set()

            def on_device(device, ups):
                settled.add(id(device))
                report(("device_updated", device, list(ups)))

            updates = engine.find_all_updates(
                devices, upgrades, self.ctx,
                progress=lambda text, done, total: report(("scan_progress", text, done, total)),
                on_start=lambda device: report(("device_started", device)), on_device=on_device)
            # Whatever the engine did not report device by device still reaches its row.
            late: dict[int, tuple] = {}
            for u in updates:
                if id(u.device) not in settled:
                    late.setdefault(id(u.device), (u.device, []))[1].append(u)
            for device in devices:
                if id(device) not in settled and id(device) not in late:
                    late[id(device)] = (device, [])
            for device, ups in late.values():
                on_device(device, ups)
            for n, update in enumerate(updates, 1):
                report(("update_verifying", update, n, len(updates)))
                engine.verify_update(update, self.ctx)
                report(("update_verified", update, n, len(updates)))
            return devices, updates

        worker = ScanWorker(work, self)
        worker.devices_enumerated.connect(self.on_devices_enumerated)
        worker.device_started.connect(self.model.mark_scanning)
        worker.device_updated.connect(self.model.set_device_result)
        worker.update_verifying.connect(self.on_update_verifying)
        worker.update_verified.connect(self.on_update_verified)
        worker.scan_progress.connect(self.on_scan_progress)
        self.run_in_background(work, self.scan_done, worker=worker)

    def on_devices_enumerated(self, devices) -> None:
        self.model.load_devices(devices)
        self.say(f"Found {len(devices)} devices. Looking for updates…")

    def on_scan_progress(self, text: str, done: int, total: int) -> None:
        if total:
            self.progress_count(done, total)
            self.say(f"Scanning {done} / {total} devices… ({text})" if done < total
                     else f"Scanned {total} devices.")
        else:
            self.progress_pulse()
            self.say(text)

    def on_update_verifying(self, update, n: int, total: int) -> None:
        self.progress_count(n - 1, total)
        self.say(f"Downloading and verifying {n} / {total}: {update.name[:60]}")

    def on_update_verified(self, update, n: int, total: int) -> None:
        self.model.refresh_update(update)
        self.progress_count(n, total)

    def scan_done(self, result) -> None:
        self.model.finish_pending()                 # nothing keeps spinning after the scan ends
        if isinstance(result, Exception):
            self.say(f"Scan failed: {result}", "error")
            return
        self.model.refresh_all()
        if not self.show_notes():
            self.say(self.idle_summary())
        self.update_controls()

    # --------------------------------------------------------- selection
    def toggle_full(self) -> None:
        """Ticked (from unticked or half-ticked) selects every Full row; unticked clears them."""
        self.model.set_full_selected(self.model.full_state() != Qt.Checked)
        self.say(self.idle_summary())

    # ----------------------------------------------------------- details
    def open_details(self, index: QModelIndex) -> None:
        row = self.model.row(index)
        if row.update is None or not row.update.checks:
            return
        rect = self.view.visualRect(index.siblingAtColumn(COL_VERIFY))
        self.show_popover(index, self.view.viewport().mapToGlobal(rect.bottomLeft()))

    def show_popover(self, index: QModelIndex, point) -> None:
        row = self.model.row(index)
        if row.update is None:
            return
        if self.popover is not None:
            try:
                self.popover.close()
            except RuntimeError:                  # already deleted
                pass
        self.popover = ChecksPopover(self, row.update)
        self.popover.show_at(point)

    # ----------------------------------------------------------- install
    def do_install(self, allow_without_snapshot: bool = False, allow_without_blocklist: bool = False) -> None:
        todo = self.model.selected_updates()
        if not todo or self.busy:
            return
        self.overrides = (allow_without_snapshot, allow_without_blocklist)
        plan = engine.dry_run_plan(todo)
        if self.ctx.demo:
            self.log.appendPlainText("\n--- DEMO: never installs. A real run would do this: ---")
            for line in plan:
                self.log.appendPlainText("  " + line)
            self.btn_log.setChecked(True)
            self.say("Demo: nothing was installed. The plan is in the log.", "warn")
            return
        if not (allow_without_snapshot or allow_without_blocklist) and not self.ask(
                *dialogs.install_confirmation(todo, plan)):
            self.say("Cancelled. Nothing was installed.")
            return
        self.say("Installing… waiting for administrator approval.")
        self.progress_pulse()                      # one elevated helper run: nothing to count
        self.run_in_background(lambda report: engine.apply(todo, self.ctx, allow_without_snapshot=allow_without_snapshot,
                                                           allow_without_blocklist=allow_without_blocklist),
                               self.install_done)

    def install_done(self, result) -> None:
        if isinstance(result, ElevationError):
            self.say(f"Nothing was installed: administrator rights were not granted ({result}).", "error")
            return
        if isinstance(result, Exception):
            self.say(f"Install failed: {result}", "error")
            return
        no_snapshot, no_blocklist = self.overrides
        status = result.get("status")
        if status == "security_alert":
            self.model.refresh_all()               # the blocked row now shows verification None
            self.say(f"BLOCKED. Nothing was installed. {result.get('detail', '')} The package was deleted.", "error")
            return
        if status == "blocklist_unavailable":
            if self.ask("Vulnerable-driver check unavailable",
                        "The LOLDrivers list of known vulnerable drivers could not be downloaded, so the drivers "
                        "cannot be checked against it. Nothing has been installed yet.\n\nContinue without this check?",
                        result.get("detail", ""), "Continue without the check"):
                return self.do_install(no_snapshot, True)
            self.say("Nothing was installed. " + result.get("detail", ""), "error")
            return
        if status == "snapshot_failed":
            if not result.get("snapshot_required") and self.ask(
                    "No restore point", "A restore point could not be created. Nothing has been installed yet.\n\n"
                    "Continue without one?", result.get("detail", ""), "Continue without restore point"):
                return self.do_install(True, no_blocklist)
            self.say("Nothing was installed. " + result.get("detail", ""), "error")
            return
        items = result.get("items", [])
        self.model.apply_outcomes(items)
        good = sum(1 for i in items if i.get("status") in ("installed", "reboot-required", "no-op"))
        bad = len(items) - good
        text = f"{good} installed, {bad} failed." + (" Restart to finish." if result.get("reboot_required") else "")
        if status == "refused" and not items:
            text = result.get("detail") or "Nothing was installed."
        self.say(text, "error" if bad or status == "refused" else "ok")

    # ------------------------------------------------------------- close
    def closeEvent(self, event):
        try:
            common.audit_log().listeners.remove(self._listener)
        except ValueError:
            pass
        if self.worker and self.worker.isRunning():
            self.worker.wait(10000)               # leave no thread behind
        event.accept()


def create(ctx: engine.Context, workdir: Path, autoscan: bool = False, theme_name: str | None = None):
    app = QApplication.instance() or QApplication(["driver-installer"])
    app.setApplicationName(TITLE)
    app.setStyle("Fusion")
    theme.register_fonts()
    theme.set_current(settings.startup_theme(theme_name))
    win = MainWindow(ctx, workdir)
    if autoscan:
        win.start_scan()
    return app, win


def settle(app, win, timeout: float = 60.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        app.processEvents()
        if not win.busy:
            return
        time.sleep(0.005)
    raise TimeoutError("background work did not finish")


def run(ctx: engine.Context, workdir: Path, shot: str | None = None, theme_name: str | None = None) -> int:
    app, win = create(ctx, workdir, theme_name=theme_name)
    win.show()
    win.start_scan()                              # scan as soon as the window opens
    if shot:                                      # scripted walkthrough for headless screenshots; never installs
        settle(app, win)
        win.toggle_full()
        app.processEvents()
        win.grab().save(shot)
        win.close()
        return 0
    return app.exec()
