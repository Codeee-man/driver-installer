"""SafeDriver GUI (PySide6): Scan -> Review updates & hashes -> Install.

The window never runs elevated. "Install" shows the exact plan, asks for
confirmation, and only then calls engine.apply(), which raises the UAC /
polkit prompt for the one-shot helper. Closing the window leaves no thread or
process behind.
"""
from __future__ import annotations

import json
from pathlib import Path

from core import common, engine, manifest
from core.common import ElevationError

STYLE = """
* { font-family: 'Segoe UI', 'Inter', 'Noto Sans', sans-serif; font-size: 13px; color: #d7dce2; }
QMainWindow, QWidget, QMessageBox { background: #14171c; }
QLabel#title { font-size: 18px; font-weight: 600; color: #f2f4f7; }
QLabel#step { color: #6b7684; padding: 4px 10px; border-radius: 10px; background: #1b2027; }
QLabel#step[active="true"] { color: #0f1216; background: #5eead4; font-weight: 600; }
QLabel#banner { padding: 8px 12px; border-radius: 6px; background: #3b1620; color: #fda4af; }
QLabel#banner[kind="ok"] { background: #12332f; color: #5eead4; }
QTableWidget { background: #181c22; border: 1px solid #252b33; border-radius: 6px; gridline-color: transparent;
               selection-background-color: #222831; alternate-background-color: #1b2027; }
QHeaderView::section { background: #181c22; color: #8793a1; border: none; border-bottom: 1px solid #252b33;
                       padding: 6px; font-weight: 600; }
QPlainTextEdit, QTextEdit { background: #101317; border: 1px solid #252b33; border-radius: 6px; color: #8793a1;
                 font-family: 'Cascadia Mono', 'DejaVu Sans Mono', monospace; font-size: 11px; }
QPushButton { background: #222831; border: 1px solid #303844; border-radius: 6px; padding: 8px 16px; }
QPushButton:hover { background: #2a323d; }
QPushButton:disabled { color: #4b5563; background: #181c22; border-color: #222831; }
QPushButton#primary { background: #5eead4; color: #0f1216; border: none; font-weight: 600; }
QPushButton#primary:disabled { background: #1f3b38; color: #4b6b66; }
"""
COLOURS = {"verified": "#5eead4", "failed": "#fb7185", "delegated": "#93c5fd", "pending": "#fbbf24",
           "installed": "#5eead4", "reboot-required": "#5eead4", "no-op": "#93c5fd", "refused": "#fb7185"}


def create(ctx: engine.Context, workdir: Path):
    """Build the application and main window; returns (app, window). Separate from run() so tests can drive it."""
    from PySide6 import QtCore, QtGui, QtWidgets

    class Worker(QtCore.QThread):
        done = QtCore.Signal(object)

        def __init__(self, fn):
            super().__init__()
            self.fn = fn

        def run(self):
            try:
                self.done.emit(self.fn())
            except Exception as exc:  # surfaced in the banner
                self.done.emit(exc)

    class Window(QtWidgets.QMainWindow):
        log_line = QtCore.Signal(str)
        COLS = ["", "Device", "Installed", "Available", "Source", "SHA-256 (from signed manifest)", "Status"]

        def __init__(self):
            super().__init__()
            self.ctx = ctx
            self.setWindowTitle(f"{common.APP} {common.VERSION}")
            self.resize(1080, 640)
            self.devices, self.updates, self.worker, self.outcome = [], [], None, {}
            self.overrides = (False, False)
            self.ask = self._ask_dialog          # replaced in the headless walkthrough
            root = QtWidgets.QWidget()
            self.setCentralWidget(root)
            lay = QtWidgets.QVBoxLayout(root)
            lay.setContentsMargins(18, 16, 18, 16)
            lay.setSpacing(12)

            head = QtWidgets.QHBoxLayout()
            title = QtWidgets.QLabel(common.APP + ("  -  demo data" if ctx.demo else ""))
            title.setObjectName("title")
            head.addWidget(title)
            head.addStretch()
            self.steps = []
            for text in ("1  Scan", "2  Review updates & hashes", "3  Install"):
                lab = QtWidgets.QLabel(text)
                lab.setObjectName("step")
                self.steps.append(lab)
                head.addWidget(lab)
            lay.addLayout(head)

            self.banner = QtWidgets.QLabel()
            self.banner.setObjectName("banner")
            self.banner.setWordWrap(True)
            self.banner.hide()
            lay.addWidget(self.banner)

            self.table = QtWidgets.QTableWidget(0, len(self.COLS))
            self.table.setHorizontalHeaderLabels(self.COLS)
            self.table.verticalHeader().hide()
            self.table.setAlternatingRowColors(True)
            self.table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
            self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
            self.table.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
            hh = self.table.horizontalHeader()
            hh.setSectionResizeMode(QtWidgets.QHeaderView.ResizeToContents)
            hh.setSectionResizeMode(1, QtWidgets.QHeaderView.Interactive)
            hh.setSectionResizeMode(6, QtWidgets.QHeaderView.Stretch)
            self.table.setColumnWidth(1, 330)
            lay.addWidget(self.table, 3)

            self.log = QtWidgets.QPlainTextEdit(readOnly=True)
            self.log.setMaximumBlockCount(500)
            self.log.setLineWrapMode(QtWidgets.QPlainTextEdit.NoWrap)
            lay.addWidget(self.log, 1)

            row = QtWidgets.QHBoxLayout()
            self.status = QtWidgets.QLabel("Ready. Nothing runs until you press Scan.")
            row.addWidget(self.status, 1)
            self.btn_scan = QtWidgets.QPushButton("Scan")
            self.btn_verify = QtWidgets.QPushButton("Download && verify selected")
            self.btn_install = QtWidgets.QPushButton("Install selected...")
            for b in (self.btn_scan, self.btn_verify, self.btn_install):
                row.addWidget(b)
            self.btn_scan.setObjectName("primary")
            self.btn_verify.setEnabled(False)
            self.btn_install.setEnabled(False)
            lay.addLayout(row)

            self.btn_scan.clicked.connect(self.do_scan)
            self.btn_verify.clicked.connect(self.do_verify)
            self.btn_install.clicked.connect(self.do_install)
            self.log_line.connect(self.log.appendPlainText)
            self._listener = lambda rec: self.log_line.emit(
                f"{rec['ts'][11:19]}  {rec['event']:<22} {json.dumps(rec['data'], default=str)[:160]}")
            common.audit_log().listeners.append(self._listener)
            self.set_step(0)

        # ---- helpers
        def set_step(self, index):
            for i, lab in enumerate(self.steps):
                lab.setProperty("active", "true" if i == index else "false")
                lab.style().unpolish(lab)
                lab.style().polish(lab)

        def alert(self, text, kind="error"):
            self.banner.setProperty("kind", kind)
            self.banner.style().unpolish(self.banner)
            self.banner.style().polish(self.banner)
            self.banner.setText(text)
            self.banner.setVisible(bool(text))

        def _ask_dialog(self, title, text, details, accept_label):
            """Safety confirmation. Default button is Cancel; Enter does not install."""
            box = QtWidgets.QMessageBox(self)
            box.setWindowTitle(title)
            box.setIcon(QtWidgets.QMessageBox.Warning)
            box.setText(text)
            box.setDetailedText(details)
            accept = box.addButton(accept_label, QtWidgets.QMessageBox.AcceptRole)
            cancel = box.addButton(QtWidgets.QMessageBox.Cancel)
            box.setDefaultButton(cancel)
            box.exec()
            return box.clickedButton() is accept

        def busy(self, fn, then):
            for b in (self.btn_scan, self.btn_verify, self.btn_install):
                b.setEnabled(False)
            self.worker = Worker(fn)
            self.worker.done.connect(then)
            self.worker.start()

        def cell(self, text, colour=None, mono=False, tip=None):
            item = QtWidgets.QTableWidgetItem(text)
            item.setToolTip(tip or text)
            if colour:
                item.setForeground(QtGui.QColor(colour))
            if mono:
                item.setFont(QtGui.QFont("DejaVu Sans Mono", 9))
            return item

        def key(self, u):
            return engine.update_key(u)

        def refresh(self):
            pending = {id(u.device) for u in self.updates}
            others = [d for d in self.devices if id(d) not in pending]
            self.table.setRowCount(len(self.updates) + len(others))
            for r, u in enumerate(self.updates):
                old = self.table.item(r, 0)
                box = QtWidgets.QTableWidgetItem()
                box.setFlags(QtCore.Qt.ItemIsUserCheckable | QtCore.Qt.ItemIsEnabled)
                box.setCheckState(old.checkState() if old and old.flags() & QtCore.Qt.ItemIsUserCheckable
                                  else QtCore.Qt.Checked)
                self.table.setItem(r, 0, box)
                done = self.outcome.get(self.key(u))
                state = done["status"] if done else u.status
                text = (f"{done['status']}: {done['detail']}" if done else
                        u.detail if u.status != "pending" else "update available - not yet verified")
                sha = f"{u.sha256[:20]}...{u.sha256[-8:]}" if u.sha256 else "-"
                for c, val in enumerate([u.name, u.installed, u.available, u.source, sha, text], 1):
                    self.table.setItem(r, c, self.cell(val, COLOURS.get(state) if c == 6 else None, mono=c == 5,
                                                       tip=u.sha256 if c == 5 else None))
            for r, d in enumerate(others, len(self.updates)):
                self.table.setItem(r, 0, self.cell(""))
                for c, val in enumerate([d.name, d.driver_version or "-", "-", d.source, "-",
                                         "; ".join(d.notes) or "no update offered"], 1):
                    self.table.setItem(r, c, self.cell(val, "#6b7684"))

        def selected(self):
            return [u for r, u in enumerate(self.updates) if self.table.item(r, 0).checkState() == QtCore.Qt.Checked]

        # ---- 1 scan
        def show_notes(self):
            if self.ctx.notes:
                self.alert("; ".join(self.ctx.notes))
                self.ctx.notes.clear()

        def do_scan(self):
            self.alert("")
            self.status.setText("Scanning hardware and looking for updates..."
                                if engine.discovery_enabled(self.ctx) else "Scanning hardware...")

            def work():
                devices, upgrades = engine.scan()
                if self.ctx.demo and self.ctx.manifest is None:
                    import demo
                    self.ctx = demo.build(devices, workdir)
                return devices, engine.find_all_updates(devices, upgrades, self.ctx)
            self.busy(work, self.scan_done)

        def scan_done(self, result):
            self.btn_scan.setEnabled(True)
            if isinstance(result, Exception):
                return self.alert(f"Scan failed: {result}")
            (self.devices, self.updates), self.outcome = result, {}
            self.table.clearContents()
            self.refresh()
            self.set_step(1)
            self.btn_verify.setEnabled(bool(self.updates))
            self.status.setText(f"{len(self.devices)} devices, {len(self.updates)} updates available.")
            self.show_notes()

        # ---- 2 verify
        def do_verify(self):
            self.alert("")
            chosen = self.selected()
            self.status.setText(f"Downloading and verifying {len(chosen)} package(s)...")
            self.busy(lambda: [engine.verify_update(u, self.ctx) for u in chosen], self.verify_done)

        def verify_done(self, result):
            self.btn_scan.setEnabled(True)
            self.btn_verify.setEnabled(True)
            if isinstance(result, Exception):
                return self.alert(f"Verification step failed: {result}")
            self.refresh()
            self.show_notes()
            failed = [u for u in self.updates if u.status == "failed"]
            alerts = [u for u in failed if "SECURITY ALERT" in u.detail]
            if alerts:
                self.alert(alerts[0].detail)
            elif failed:
                self.alert("Verification failed for: " + "; ".join(u.name for u in failed) +
                           ". The downloaded file was deleted and will not be installed.")
            todo = engine.ready(self.selected())
            self.btn_install.setEnabled(bool(todo))
            self.status.setText(f"{len(todo)} verified and ready, {len(failed)} rejected.")

        # ---- 3 install
        def do_install(self, allow_without_snapshot=False, allow_without_blocklist=False):
            self.overrides = (allow_without_snapshot, allow_without_blocklist)
            todo = engine.ready(self.selected())
            if not todo:
                return
            plan = engine.dry_run_plan(todo)
            self.set_step(2)
            if self.ctx.demo:
                self.log.appendPlainText("\n--- DEMO: never installs. A real run would do this: ---")
                for line in plan:
                    self.log.appendPlainText("  " + line)
                self.status.setText("Demo complete. Nothing was changed on this system.")
                return
            if not (allow_without_snapshot or allow_without_blocklist) and not self.ask(
                    "Install drivers",
                    f"Install {len(todo)} verified update(s)?\n\nA restore point is created first. "
                    "You will be asked for administrator rights.",
                    "\n".join(f"{u.name}: {u.installed} -> {u.available}" for u in todo) + "\n\n" + "\n".join(plan),
                    "Install"):
                self.status.setText("Cancelled. Nothing was installed.")
                return
            self.status.setText("Installing... waiting for the elevated helper.")
            self.busy(lambda: engine.apply(todo, self.ctx, allow_without_snapshot=allow_without_snapshot,
                                           allow_without_blocklist=allow_without_blocklist), self.install_done)

        def install_done(self, result):
            self.btn_scan.setEnabled(True)
            self.btn_verify.setEnabled(True)
            self.btn_install.setEnabled(True)
            if isinstance(result, ElevationError):
                self.status.setText("Nothing was installed.")
                return self.alert(f"Administrator rights were not granted: {result}")
            if isinstance(result, Exception):
                return self.alert(f"Install failed: {result}")
            no_snapshot, no_blocklist = self.overrides
            if result["status"] == "security_alert":
                self.refresh()
                self.status.setText("BLOCKED. Nothing was installed.")
                return self.alert(result["detail"] + " The downloaded package was deleted.")
            if result["status"] == "blocklist_unavailable":
                if self.ask("Vulnerable-driver check unavailable",
                            "The LOLDrivers list of known vulnerable drivers could not be downloaded, so the "
                            "drivers cannot be checked against it. Nothing has been installed yet.\n\n"
                            "Continue without this check?", result["detail"], "Continue without the check"):
                    return self.do_install(no_snapshot, True)
                self.status.setText("Nothing was installed.")
                return self.alert(result["detail"])
            if result["status"] == "snapshot_failed":
                if not result.get("snapshot_required") and self.ask(
                        "No restore point", "A restore point could not be created. Nothing has been installed yet.\n\n"
                        "Continue without one?", result["detail"], "Continue without restore point"):
                    return self.do_install(True, no_blocklist)
                self.status.setText("Nothing was installed.")
                return self.alert(result["detail"])
            self.outcome = {i["id"]: i for i in result.get("items", [])}
            self.refresh()
            good = sum(1 for i in self.outcome.values() if i["status"] in ("installed", "reboot-required", "no-op"))
            bad = len(self.outcome) - good
            text = f"{good} installed, {bad} failed." + (" Restart to finish." if result.get("reboot_required") else "")
            self.status.setText(text)
            self.alert((result.get("detail") or text) if bad or result["status"] == "refused" else text,
                       "error" if bad or result["status"] == "refused" else "ok")

        def closeEvent(self, event):
            common.audit_log().listeners.remove(self._listener)
            if self.worker and self.worker.isRunning():
                self.worker.wait(5000)
            event.accept()

    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication(["safedriver"])
    app.setStyle("Fusion")
    app.setStyleSheet(STYLE)
    return app, Window()


def settle(app, win) -> None:
    """Process events until the window's background worker has finished."""
    while win.worker and win.worker.isRunning():
        app.processEvents()
    app.processEvents()
    app.processEvents()


def run(ctx: engine.Context, workdir: Path, shot: str | None = None) -> int:
    app, win = create(ctx, workdir)
    win.show()
    if shot:  # scripted walkthrough for headless testing; never confirms an install
        win.ask = lambda *a: False
        win.do_scan()
        settle(app, win)
        if win.btn_verify.isEnabled():
            win.do_verify()
            settle(app, win)
        if win.btn_install.isEnabled():
            win.do_install()
            settle(app, win)
        win.grab().save(shot)
        win.close()
        return 0
    return app.exec()
