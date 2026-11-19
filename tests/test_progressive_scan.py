"""Progressive scanning: every device appears right after enumeration, each row settles in place
when its own lookup finishes (with a spinner until then), and the progress bar pulses or counts.
Covers the engine callbacks, ScanWorker's signals, the model's row phases and the window."""
import os
import threading
import time

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6")

from PySide6.QtCore import QCoreApplication, QItemSelectionModel  # noqa: E402

import gui  # noqa: E402
import ui  # noqa: E402
from core import common, engine, scanner_win  # noqa: E402
from core.discovery import linux_lvfs, ms_catalog, windows_update  # noqa: E402
from core.model import Device, Update  # noqa: E402
from ui import theme  # noqa: E402
from ui.models import (COL_STATUS, DONE, NOT_CHECKED, QUEUED, SCANNING, BadgeRole, DriverTableModel,  # noqa: E402
                       SpinnerRole, SubtitleRole)
from ui.workers import ScanWorker  # noqa: E402
from test_gui import FULL_CHECKS  # noqa: E402


def pump(app, until, timeout=10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        app.processEvents()
        if until():
            return
        time.sleep(0.005)
    raise AssertionError("condition not reached")


def status(model, row):
    return model.index(row, COL_STATUS).data(BadgeRole)[0]


def names(model):
    return [r.device.name for r in model.rows]


# ------------------------------------------------------------------ engine
def test_engine_reports_each_device_as_soon_as_its_lookup_is_final(runner, windows, monkeypatch):
    wifi, nic, acpi = (Device("Wifi", hardware_ids=["PCI\\VEN_8086&DEV_2725"]),
                       Device("Nic", hardware_ids=["PCI\\VEN_10EC&DEV_8125"]), Device("ACPI button"))
    covered = Device("Gpu", hardware_ids=["pci:10de:2504"], driver_version="1.0")
    manifest_update = Update(covered, "Gpu driver", "1.0", "2.0", "vendor", "", {"id": "gpu"}, "pending")
    monkeypatch.setattr(engine.manifest, "find_updates", lambda d, m, u: [manifest_update])
    monkeypatch.setattr(windows_update, "discover", lambda devs: ([], []))
    events = []

    def catalog(devs, progress=None, on_result=None):
        for dev in devs:
            if dev is wifi:
                progress(dev)
                events.append(("lookup", dev.name))
                on_result(dev, {"name": "Wifi 2", "version": "2.0", "origin": "ms-catalog", "id_confirmed": True})
            else:
                on_result(dev, None)
        return [(wifi, {"name": "Wifi 2", "version": "2.0", "origin": "ms-catalog"})]
    monkeypatch.setattr(scanner_win, "discover_updates", catalog)
    ups = engine.find_all_updates(
        [covered, wifi, nic, acpi], {}, engine.Context(discover=True),
        progress=lambda text, done, total: events.append(("progress", text, done, total)),
        on_start=lambda d: events.append(("start", d.name)),
        on_device=lambda d, u: events.append(("device", d.name, [x.name for x in u])))
    devices = [e for e in events if e[0] == "device"]
    assert devices == [("device", "Gpu", ["Gpu driver"]), ("device", "Wifi", ["Wifi 2"]),
                       ("device", "Nic", []), ("device", "ACPI button", [])]           # each once, manifest first
    assert events.index(("start", "Wifi")) < events.index(("device", "Wifi", ["Wifi 2"]))
    progress = [e for e in events if e[0] == "progress"]
    assert ("progress", "Asking Windows Update which drivers it offers this PC…", 1, 0) in progress   # pulse
    assert progress[-1][2:] == (4, 4)                                                   # determinate, complete
    assert [u.name for u in ups] == ["Gpu driver", "Wifi 2"]


def test_unreachable_catalog_still_settles_every_device(runner, windows, monkeypatch):
    devs = [Device("Wifi", hardware_ids=["PCI\\VEN_8086&DEV_2725"]), Device("Nic")]
    offered = {"name": "WU Wifi", "version": "3.0", "origin": "windows-update", "id_confirmed": True}
    monkeypatch.setattr(windows_update, "discover", lambda d: ([(devs[0], offered)], []))

    def down(d, progress=None, on_result=None):
        raise ms_catalog.CatalogError("connection refused")
    monkeypatch.setattr(scanner_win, "discover_updates", down)
    seen = []
    ups = engine.find_all_updates(devs, {}, engine.Context(discover=True),
                                  on_device=lambda d, u: seen.append((d.name, [x.name for x in u])))
    assert seen == [("Wifi", ["WU Wifi"]), ("Nic", [])] and [u.name for u in ups] == ["WU Wifi"]


def test_linux_recommendation_for_an_unlisted_device_is_reported(runner, monkeypatch):
    monkeypatch.setattr(common, "OS_NAME", "linux")
    gpu = Device("GPU", hardware_ids=["pci:10de:2504"])
    rec = linux_lvfs.Recommendation("nvidia-driver-550", "apt-get", "ubuntu-drivers", "", "recommended")
    monkeypatch.setattr(linux_lvfs, "driver_recommendations", lambda d: [rec])
    seen = []
    engine.find_all_updates([gpu], {}, engine.Context(discover=True),
                            on_device=lambda d, u: seen.append((d.name, len(u))))
    assert seen == [("This computer", 1), ("GPU", 0)]


# ------------------------------------------------------------------ worker
def test_scan_worker_routes_events_to_typed_signals(tmp_path):
    app = gui.create(engine.Context(manifest={"packages": []}), tmp_path)[0]
    dev, update = Device("Wifi"), object()
    worker = ScanWorker(lambda report: [report(m) for m in (
        ("devices_enumerated", [dev]), ("device_started", dev), ("device_updated", dev, [update]),
        ("update_verifying", update, 1, 1), ("update_verified", update, 1, 1),
        ("scan_progress", "Microsoft Update Catalog", 1, 1), "something else")] and "result")
    got = []
    for name in ScanWorker.SIGNALS:
        getattr(worker, name).connect(lambda *a, n=name: got.append((n, a)))
    worker.progress.connect(lambda m: got.append(("progress", (m,))))
    worker.done.connect(lambda r: got.append(("done", (r,))))
    worker.start()
    pump(app, lambda: got and got[-1][0] == "done")
    worker.wait()
    assert [g[0] for g in got] == list(ScanWorker.SIGNALS) + ["progress", "done"]
    assert got[2][1] == (dev, [update]) and got[5][1] == ("Microsoft Update Catalog", 1, 1)
    assert got[-1][1] == ("result",)


# ------------------------------------------------------------------- model
@pytest.fixture
def model(tmp_path):
    gui.create(engine.Context(manifest={"packages": []}), tmp_path)
    return DriverTableModel()


def verified(update):
    for key, state, reason in FULL_CHECKS:
        update.set_check(key, state, reason)
    update.status = "verified"
    return update


def test_rows_appear_queued_then_settle_in_place(model):
    devs = [Device("Audio", driver_version="6.0"), Device("Wifi", driver_version="1.0"), Device("Usb")]
    spins = []
    model.spinningChanged.connect(spins.append)
    model.load_devices(devs)
    assert names(model) == ["Audio", "Wifi", "Usb"] and all(r.phase == QUEUED for r in model.rows)
    assert all(model.index(i, COL_STATUS).data(SpinnerRole) for i in range(3)) and spins == [True]
    assert status(model, 0) == "Queued" and "6.0 · waiting to look for updates" in model.index(0, 0).data(SubtitleRole)
    model.mark_scanning(devs[0])
    assert status(model, 0) == "Scanning…" and "looking for updates" in model.index(0, 0).data(SubtitleRole)
    model.set_device_result(devs[0], [])
    assert model.rows[-1].device is devs[0] and model.rows[-1].phase == DONE        # up to date: to the bottom
    assert status(model, 2) == "Up to date" and not model.index(2, COL_STATUS).data(SpinnerRole)
    update = Update(devs[1], "Wifi driver", "1.0", "2.0", "Windows Update", "", {"id": "w"}, "pending")
    model.set_device_result(devs[1], [update])
    assert names(model) == ["Wifi", "Usb", "Audio"]                                # update: to the top
    assert status(model, 0) == "Checking…" and model.index(0, COL_STATUS).data(SpinnerRole)   # verifying
    model.refresh_update(verified(update))
    assert status(model, 0) == "To update" and model.rows[0].level == "Full" and model.rows[0].selectable
    assert model.spinning and spins == [True]                                      # Usb is still queued
    model.set_device_result(devs[2], [])
    assert not model.spinning and spins == [True, False]                           # all final: timer may stop
    assert [status(model, i) for i in range(3)] == ["To update", "Up to date", "Up to date"]


def test_resorting_keeps_the_view_selection_on_the_same_device(model):
    from PySide6.QtWidgets import QTableView
    devs = [Device("Audio"), Device("Wifi")]
    model.load_devices(devs)
    view = QTableView()
    view.setModel(model)
    view.selectionModel().select(model.index(1, 0), QItemSelectionModel.ClearAndSelect | QItemSelectionModel.Rows)
    model.set_device_result(devs[1], [Update(devs[1], "Wifi driver", "1", "2", "WU", "", {"id": "w"}, "pending")])
    (selected,) = view.selectionModel().selectedRows()
    assert selected.row() == 0 and model.rows[0].device is devs[1]


def test_unlisted_device_gets_new_rows_and_a_failed_scan_stops_spinning(model):
    devs = [Device("Audio"), Device("Wifi")]
    model.load_devices(devs)
    system = Device("This computer", kind="system")
    model.set_device_result(system, [Update(system, "nvidia-driver-550", "-", "550", "distro", "", {"id": "n"}, "delegated")])
    assert names(model)[0] == "This computer" and len(model.rows) == 3
    model.finish_pending()
    assert [r.phase for r in model.rows] == [NOT_CHECKED] * 3 and not model.spinning
    assert status(model, 1) == "Not checked" and model.counts()["not_checked"] == 3


# ------------------------------------------------------------------ window
def test_window_shows_devices_before_the_online_lookup_finishes(tmp_path, windows, runner, monkeypatch):
    devs = [Device("Audio", driver_version="6.0"), Device("Wifi", driver_version="1.0"), Device("Usb")]
    update = Update(devs[1], "Wifi driver", "1.0", "2.0", "Windows Update", "", {"id": "w"}, "pending")
    halfway, release = threading.Event(), threading.Event()
    enumerating = threading.Event()

    def scan():
        enumerating.wait(10)
        return devs, {}

    def lookups(devices, upgrades, ctx, progress=None, on_start=None, on_device=None):
        progress("Asking Windows Update which drivers it offers this PC…", 0, 0)
        progress("Microsoft Update Catalog", 0, 3)
        on_start(devs[0])
        on_device(devs[0], [])
        progress("Microsoft Update Catalog", 1, 3)
        on_start(devs[1])
        halfway.set()
        release.wait(10)
        on_device(devs[1], [update])
        on_device(devs[2], [])
        progress("Microsoft Update Catalog", 3, 3)
        return [update]
    monkeypatch.setattr(engine, "scan", scan)
    monkeypatch.setattr(engine, "find_all_updates", lookups)
    monkeypatch.setattr(engine, "verify_update", lambda u, ctx, progress=None: verified(u))
    app, win = ui.create(engine.Context(manifest={"packages": []}), tmp_path, autoscan=True)
    try:
        # Stage 1 not done yet: indeterminate bar, nothing to count
        assert win.progress.isVisibleTo(win) and win.progress.maximum() == 0 and win.counter.text() == ""
        enumerating.set()
        pump(app, lambda: halfway.is_set() and win.counter.text() == "1 / 3")
        m = win.model
        assert len(m.rows) == 3                                       # every device is already listed
        assert (win.progress.maximum(), win.progress.value()) == (3, 1)
        assert win.status.text() == "> Scanning 1 / 3 devices… (Microsoft Update Catalog)"
        assert {r.device.name: status(m, i) for i, r in enumerate(m.rows)} == {
            "Wifi": "Scanning…", "Usb": "Queued", "Audio": "Up to date"}
        assert win.spinner.running and not win.btn_rescan.isEnabled()
        release.set()
        ui.settle(app, win)
        assert names(m) == ["Wifi", "Audio", "Usb"] and status(m, 0) == "To update" and m.rows[0].level == "Full"
        assert not win.spinner.running                               # all rows final: no timer, no CPU
        assert not win.progress.isVisibleTo(win) and win.counter.text() == ""
        assert win.status.text() == "> 1 update(s) found · 0 selected · 3 devices"
    finally:
        enumerating.set()
        release.set()
        win.close()


def test_failed_scan_leaves_no_row_spinning(tmp_path, windows, runner, monkeypatch):
    devs = [Device("Audio"), Device("Wifi")]
    monkeypatch.setattr(engine, "scan", lambda: (devs, {}))

    def broken(devices, upgrades, ctx, **kw):
        kw["on_device"](devs[0], [])
        raise RuntimeError("catalog parser exploded")
    monkeypatch.setattr(engine, "find_all_updates", broken)
    app, win = ui.create(engine.Context(manifest={"packages": []}), tmp_path, autoscan=True)
    ui.settle(app, win)
    assert [status(win.model, i) for i in range(2)] == ["Not checked", "Up to date"]
    assert not win.spinner.running and not win.progress.isVisibleTo(win)
    assert "Scan failed: catalog parser exploded" in win.status.text()
    win.close()


def test_install_pulses_the_progress_bar_until_it_finishes(tmp_path, windows, runner, monkeypatch):
    from test_gui import make_update
    app, win = gui.create(engine.Context(manifest={"packages": []}), tmp_path)
    upd = make_update("Wifi", FULL_CHECKS)
    win.model.load([upd.device], [upd])
    win.model.set_selected(0, True)
    win.ask = lambda *a, **k: True
    started, release = threading.Event(), threading.Event()

    def apply(todo, ctx, **kw):
        started.set()
        release.wait(10)
        return {"status": "ok", "items": [{"id": engine.update_key(upd), "status": "installed"}]}
    monkeypatch.setattr(engine, "apply", apply)
    win.do_install()
    try:
        pump(app, started.is_set)
        assert win.progress.isVisibleTo(win) and win.progress.maximum() == 0
    finally:
        release.set()
    ui.settle(app, win)
    assert not win.progress.isVisibleTo(win) and "1 installed" in win.status.text()
    win.close()


# ------------------------------------------------------------------- theme
@pytest.mark.parametrize("name, track, fill, border", [
    ("matrix", "#050505", "#00FF66", "#1A3320"),
    ("clean", "#15181E", "stop:0 #E8ECF2, stop:1 #C2C9D4", "#2B313C")])
def test_progress_bar_is_styled_per_theme(tmp_path, name, track, fill, border):
    gui.create(engine.Context(manifest={"packages": []}), tmp_path)
    theme.set_current(name)
    try:
        sheet = theme.stylesheet()
        bar = sheet[sheet.index("QProgressBar#progress {"):sheet.index("QLabel#counter")]
        assert f"background: {track}; border: 1px solid {border}" in bar and fill in bar
        counter = sheet[sheet.index("QLabel#counter"):]
        assert ("VT323" in counter[:200]) == (name == "matrix")
    finally:
        theme.set_current("matrix")
