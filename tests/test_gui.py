"""The PySide6 window (src/ui/), driven headlessly. engine.apply is replaced where an install
would happen, so nothing is ever installed."""
import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6")

from PySide6.QtCore import QEvent, QPoint, QPointF, Qt  # noqa: E402
from PySide6.QtGui import QMouseEvent  # noqa: E402
from PySide6.QtTest import QTest  # noqa: E402

import gui  # noqa: E402
import ui  # noqa: E402
from core import engine  # noqa: E402
from core.common import ElevationError  # noqa: E402
from core.model import Device, Update  # noqa: E402
from ui import theme  # noqa: E402
from ui import verification as vf  # noqa: E402
from ui.delegates import BadgeDelegate  # noqa: E402
from test_scanner_win import _pkg  # noqa: E402
from ui.models import (COL_DEVICE, COL_SELECT, COL_STATUS, COL_VERIFY, BadgeRole, HelpRole,  # noqa: E402
                       SubtitleRole)

OK = "passed"
FULL_CHECKS = [("sha256", OK, "bytes match the signed manifest"), ("manifest", OK, "pinned key"),
               ("blocklist", OK, "3 .sys file(s) compared: no match"), ("publisher", OK, "Authenticode: x.cat")]
PARTIAL_CHECKS = [("sha256", OK, "digest matches"), ("manifest", "not_applicable", "Microsoft Update Catalog"),
                  ("blocklist", "skipped", "LOLDrivers database offline (connection timed out)"),
                  ("publisher", OK, "Authenticode: y.cat")]
NO_AUTHENTICODE = [("sha256", OK, "digest matches"), ("manifest", OK, "pinned key"),
                   ("blocklist", OK, "no match"), ("publisher", "skipped", "Authenticode check missing")]
NONE_CHECKS = [("sha256", "failed", "SHA-256 MISMATCH"), ("manifest", OK, "pinned key"),
               ("blocklist", "skipped", "not reached"), ("publisher", "skipped", "not reached")]
FWUPD_CHECKS = [(k, "not_applicable", "fwupd verifies it") for k in ("sha256", "manifest", "blocklist", "publisher")]


def make_update(name, checks, status="verified", pid=None):
    dev = Device(name, hardware_ids=["pci:8086:2725"], driver_version="1.0")
    pkg = _pkg(pid or name.lower().replace(" ", "."), "pci:8086:2725", "2.0")
    upd = Update(dev, f"{name} driver", "1.0", "2.0", "vendor", "a" * 64, pkg, status, path="/q/pkg.zip")
    for key, state, reason in checks:
        upd.set_check(key, state, reason)
    return upd


@pytest.fixture
def window(tmp_path, windows, runner):
    app, win = gui.create(engine.Context(manifest={"packages": []}), tmp_path)
    ups = {"full": make_update("Wifi", FULL_CHECKS), "full2": make_update("Gpu", FULL_CHECKS),
           "partial": make_update("Nic", PARTIAL_CHECKS), "none": make_update("Legacy", NONE_CHECKS, "failed"),
           "fw": make_update("Ssd", FWUPD_CHECKS, "delegated")}
    devices = [u.device for u in ups.values()] + [Device("Audio", driver_version="6.0")]
    win.model.load(devices, list(ups.values()))
    win.update_controls()
    win.show()
    app.processEvents()
    win.questions = []
    yield app, win, ups
    win.close()


def row_of(win, update):
    return next(i for i, r in enumerate(win.model.rows) if r.update is update)


def answer(win, *answers):
    replies = iter(answers)

    def ask(title, text, details, accept_label):
        win.questions.append((title, text, details))
        return next(replies)
    win.ask = ask


# ------------------------------------------------------------- structure
def test_entry_point_shim_and_lazy_qt():
    assert gui.run is ui.run and gui.create is ui.create and gui.settle is ui.settle
    assert len(open(gui.__file__).read().strip().splitlines()) <= 3


def test_window_layout(window):
    app, win, _ = window
    assert win.windowTitle() == "Driver Installer" and win.title.text() == "Driver Installer"
    assert win.title.alignment() & Qt.AlignHCenter
    assert [win.model.headerData(c, Qt.Horizontal) for c in range(4)] == ["DEVICE", "STATUS", "VERIFICATION", ""]
    assert win.btn_install.text() == "Download and Install" and win.btn_install.objectName() == "primary"
    assert win.select_full.text() == "Select all fully checked"
    assert win.log.isHidden()                               # activity log is opt-in


def test_rows_are_ordered_and_badged(window):
    _, win, ups = window
    names = [r.device.name for r in win.model.rows]
    assert names == ["Gpu", "Ssd", "Wifi", "Nic", "Legacy", "Audio"]       # Full, Partial, None, then up to date
    badge = lambda row, col: win.model.index(row, col).data(BadgeRole)
    assert badge(row_of(win, ups["full"]), COL_VERIFY) == ("Full", "full")
    assert badge(row_of(win, ups["fw"]), COL_VERIFY) == ("Full", "full")     # LVFS / fwupd counts as Full
    assert badge(row_of(win, ups["partial"]), COL_VERIFY) == ("Partial", "partial")
    assert badge(row_of(win, ups["none"]), COL_VERIFY) == ("None", "none")
    assert badge(row_of(win, ups["full"]), COL_STATUS) == ("To update", "accent")
    assert badge(5, COL_STATUS) == ("Up to date", "uptodate") and badge(5, COL_VERIFY) is None
    assert win.model.index(row_of(win, ups["full"]), COL_DEVICE).data(SubtitleRole) == "1.0 → 2.0 · vendor"
    assert "no newer driver found" in win.model.index(5, COL_DEVICE).data(SubtitleRole)


def test_only_full_and_partial_rows_can_be_selected(window):
    _, win, ups = window
    for key, selectable in (("full", True), ("partial", True), ("fw", True), ("none", False)):
        idx = win.model.index(row_of(win, ups[key]), COL_SELECT)
        assert bool(idx.flags() & Qt.ItemIsUserCheckable) is selectable
        assert win.model.setData(idx, Qt.Checked, Qt.CheckStateRole) is selectable
    assert win.model.index(5, COL_SELECT).data(Qt.CheckStateRole) is None    # up to date: no checkbox


# --------------------------------------------------------------- (?) help
def test_help_target_on_partial_and_none(window):
    _, win, ups = window
    for key, has_help in (("full", False), ("partial", True), ("none", True)):
        assert bool(win.model.index(row_of(win, ups[key]), COL_VERIFY).data(HelpRole)) is has_help


def test_tooltip_names_the_skipped_check(window):
    _, win, ups = window
    tip = win.model.index(row_of(win, ups["partial"]), COL_VERIFY).data(Qt.ToolTipRole)
    assert tip.startswith("Verification: Partial")
    assert "○ LOLDrivers BYOVD check: skipped" in tip and "LOLDrivers database offline" in tip
    tip = vf.explain(make_update("x", NO_AUTHENTICODE))
    assert "Authenticode check missing" in tip


def test_clicking_the_question_mark_opens_the_check_list(window):
    app, win, ups = window
    row = row_of(win, ups["partial"])
    cell = win.view.visualRect(win.model.index(row, COL_VERIFY))
    target = BadgeDelegate.help_rect(cell, "Partial").center()
    QTest.mouseClick(win.view.viewport(), Qt.LeftButton, Qt.NoModifier, target)
    app.processEvents()
    assert win.popover is not None and win.popover.isVisible()
    text = win.popover.text()
    assert "Verification: Partial" in text and "LOLDrivers database offline (connection timed out)" in text
    assert "– Ed25519 manifest signature: not applicable" in text
    QTest.keyClick(win.popover, Qt.Key_Escape)
    app.processEvents()
    win.popover = None
    QTest.mouseClick(win.view.viewport(), Qt.LeftButton, Qt.NoModifier, cell.topLeft() + QPoint(14, 4))
    assert win.popover is None                               # clicking the badge itself does not open it


def test_keyboard_opens_details_and_toggles_selection(window):
    app, win, ups = window
    row = row_of(win, ups["full"])
    win.view.setFocus()
    win.view.setCurrentIndex(win.model.index(row, COL_DEVICE))
    QTest.keyClick(win.view, Qt.Key_Space)
    assert win.model.rows[row].selected
    QTest.keyClick(win.view, Qt.Key_Return)
    app.processEvents()
    assert win.popover is not None and "Verification: Full" in win.popover.text()


def test_badges_paint_in_the_theme_colours(window):
    app, win, ups = window
    image = win.view.viewport().grab().toImage()

    def colours(key):
        r = win.view.visualRect(win.model.index(row_of(win, ups[key]), COL_VERIFY))
        return {image.pixelColor(x, y).name() for x in range(r.left(), r.right()) for y in range(r.top(), r.bottom())}
    assert theme.ACCENT.lower() in colours("full")           # neon green Full badge
    assert theme.AMBER.lower() in colours("partial")         # amber Partial badge and (?)
    assert theme.RED.lower() in colours("none")              # red None badge


# ------------------------------------------------------- select all full
def test_select_all_fully_checked_touches_only_full_rows(window):
    _, win, ups = window
    partial = row_of(win, ups["partial"])
    win.model.set_selected(partial, True)                    # chosen by hand
    QTest.mouseClick(win.select_full, Qt.LeftButton)
    assert win.select_full.checkState() == Qt.Checked
    chosen = {r.device.name for r in win.model.rows if r.selected}
    assert chosen == {"Wifi", "Gpu", "Ssd", "Nic"}
    win.model.set_selected(row_of(win, ups["full"]), False)  # one Full row unticked by hand
    assert win.select_full.checkState() == Qt.PartiallyChecked
    QTest.mouseClick(win.select_full, Qt.LeftButton)          # half-ticked -> ticks all Full rows again
    assert win.select_full.checkState() == Qt.Checked
    QTest.mouseClick(win.select_full, Qt.LeftButton)          # unticking clears Full rows only
    assert win.select_full.checkState() == Qt.Unchecked
    assert {r.device.name for r in win.model.rows if r.selected} == {"Nic"}


def test_install_button_needs_a_selection(window):
    _, win, ups = window
    assert not win.btn_install.isEnabled()
    win.model.set_selected(row_of(win, ups["full"]), True)
    assert win.btn_install.isEnabled()
    assert "1 selected" in win.idle_summary()


# --------------------------------------------------------- startup scan
def test_window_scans_and_verifies_in_the_background(tmp_path, windows, runner, monkeypatch):
    devices = [Device("Wifi", hardware_ids=["pci:8086:2725"]), Device("Audio")]
    update = Update(devices[0], "Wifi driver", "1.0", "2.0", "vendor", "", {"id": "wifi", "install": {"method": "pnputil"}})
    monkeypatch.setattr(engine, "scan", lambda: (devices, {}))
    monkeypatch.setattr(engine, "find_all_updates", lambda d, u, ctx, **kw: [update])     # reports nothing early
    seen_pending = []

    def verify(u, ctx, progress=None):
        seen_pending.append(vf.level(u))
        for key, state, reason in FULL_CHECKS:
            u.set_check(key, state, reason)
        u.status = "verified"
    monkeypatch.setattr(engine, "verify_update", verify)
    app, win = ui.create(engine.Context(manifest={"packages": []}), tmp_path, autoscan=True)
    ui.settle(app, win)
    assert seen_pending == ["Pending"]                       # badges were not final before verification
    assert [r.level for r in win.model.rows] == ["Full", ""]
    assert win.select_full.isEnabled() and win.status.text() == "> 1 update(s) found · 0 selected · 2 devices"
    win.close()


def test_scan_failure_and_notes_are_shown(tmp_path, windows, runner, monkeypatch):
    def broken():
        raise RuntimeError("lspci exploded")
    monkeypatch.setattr(engine, "scan", broken)
    app, win = ui.create(engine.Context(manifest={"packages": []}), tmp_path, autoscan=True)
    ui.settle(app, win)
    assert win.status.text() == "> Scan failed: lspci exploded" and win.status.property("kind") == "error"
    monkeypatch.setattr(engine, "scan", lambda: ([], {}))
    win.ctx.notes.append("online discovery failed: catalog unreachable")
    win.start_scan()
    ui.settle(app, win)
    assert "catalog unreachable" in win.status.text() and win.status.property("kind") == "warn"
    win.close()


# ---------------------------------------------------------------- install
def test_cancel_installs_nothing(window, monkeypatch):
    app, win, ups = window
    monkeypatch.setattr(engine, "apply", lambda *a, **k: pytest.fail("must not install without confirmation"))
    win.model.set_selected(row_of(win, ups["full"]), True)
    answer(win, False)
    QTest.mouseClick(win.btn_install, Qt.LeftButton)
    ui.settle(app, win)
    assert win.status.text() == "> Cancelled. Nothing was installed."
    title, text, details = win.questions[0]
    assert title == "Download and Install" and "Wifi: 1.0 → 2.0" in text and "pnputil /add-driver" in details


def test_partial_selection_is_named_in_the_confirmation(window, monkeypatch):
    app, win, ups = window
    monkeypatch.setattr(engine, "apply", lambda *a, **k: pytest.fail("cancelled"))
    win.model.set_selected(row_of(win, ups["partial"]), True)
    answer(win, False)
    win.do_install()
    _, text, _ = win.questions[0]
    assert "1 of them are only partially verified" in text
    assert "Nic: LOLDrivers BYOVD check skipped (LOLDrivers database offline" in text


def test_confirmed_install_updates_each_row(window, monkeypatch):
    app, win, ups = window
    got = {}

    def fake_apply(todo, ctx, **kw):
        got["todo"] = todo
        return {"status": "ok", "reboot_required": True, "items": [
            {"id": "wifi", "name": "Wifi", "status": "reboot-required", "detail": "restart to finish"},
            {"id": "gpu", "name": "Gpu", "status": "failed", "detail": "pnputil error 5"}]}
    monkeypatch.setattr(engine, "apply", fake_apply)
    win.toggle_full()
    win.model.set_selected(row_of(win, ups["fw"]), False)
    answer(win, True)
    win.do_install()
    ui.settle(app, win)
    assert {u.device.name for u in got["todo"]} == {"Wifi", "Gpu"}
    badge = lambda key: win.model.index(row_of(win, ups[key]), COL_STATUS).data(BadgeRole)
    assert badge("full") == ("Restart required", "warn") and badge("full2") == ("Failed", "alert")
    assert win.status.text() == "> 1 installed, 1 failed. Restart to finish." and win.status.property("kind") == "error"
    assert not win.model.rows[row_of(win, ups["full"])].selectable          # installed rows cannot be picked again


def test_snapshot_failure_asks_again_before_continuing(window, monkeypatch):
    app, win, ups = window
    calls = []

    def fake_apply(todo, ctx, allow_without_snapshot=False, allow_without_blocklist=False):
        calls.append(allow_without_snapshot)
        if not allow_without_snapshot:
            return {"status": "snapshot_failed", "snapshot_required": False, "items": [],
                    "detail": "no restore point: System Restore is disabled. Nothing was installed."}
        return {"status": "ok", "items": [{"id": "wifi", "name": "x", "status": "installed", "detail": "ok"}]}
    monkeypatch.setattr(engine, "apply", fake_apply)
    win.model.set_selected(row_of(win, ups["full"]), True)
    answer(win, True, False)
    win.do_install()
    ui.settle(app, win)
    assert calls == [False] and win.questions[1][0] == "No restore point"
    assert "System Restore is disabled" in win.status.text()
    answer(win, True, True)
    win.do_install()
    ui.settle(app, win)
    assert calls == [False, False, True] and win.status.text() == "> 1 installed, 0 failed."


def test_unavailable_blocklist_asks_before_continuing_unchecked(window, monkeypatch):
    app, win, ups = window
    calls = []

    def fake_apply(todo, ctx, allow_without_snapshot=False, allow_without_blocklist=False):
        calls.append((allow_without_snapshot, allow_without_blocklist))
        if not allow_without_blocklist:
            return {"status": "blocklist_unavailable", "items": [],
                    "detail": "the LOLDrivers blocklist could not be loaded: timeout. Nothing was installed."}
        return {"status": "ok", "items": [{"id": "wifi", "name": "x", "status": "installed", "detail": "ok"}]}
    monkeypatch.setattr(engine, "apply", fake_apply)
    win.model.set_selected(row_of(win, ups["full"]), True)
    answer(win, True, False)
    win.do_install()
    ui.settle(app, win)
    assert calls == [(False, False)] and win.questions[1][0] == "Vulnerable-driver check unavailable"
    answer(win, True, True)
    win.do_install()
    ui.settle(app, win)
    assert calls[-1] == (False, True) and win.status.text() == "> 1 installed, 0 failed."


def test_security_alert_turns_the_row_red_with_no_way_around_it(window, monkeypatch):
    app, win, ups = window

    def fake_apply(todo, ctx, **kw):
        todo[0].set_check("blocklist", "failed", "SECURITY ALERT: evil.sys is a known malicious driver")
        todo[0].status = "failed"
        return {"status": "security_alert", "items": [], "alerts": ["wifi"],
                "detail": "SECURITY ALERT: evil.sys is a known malicious driver. Installation aborted."}
    monkeypatch.setattr(engine, "apply", fake_apply)
    win.model.set_selected(row_of(win, ups["full"]), True)
    answer(win, True)
    win.do_install()
    ui.settle(app, win)
    row = row_of(win, ups["full"])
    assert win.model.index(row, COL_VERIFY).data(BadgeRole) == ("None", "none")
    assert not win.model.rows[row].selected and not win.model.rows[row].selectable
    assert win.status.text().startswith("> BLOCKED. Nothing was installed. SECURITY ALERT: evil.sys")
    assert len(win.questions) == 1                           # no "continue anyway" for a blocklist hit


def test_declined_elevation_is_reported(window, monkeypatch):
    app, win, ups = window

    def declined(*a, **k):
        raise ElevationError("the UAC prompt was declined")
    monkeypatch.setattr(engine, "apply", declined)
    win.model.set_selected(row_of(win, ups["full"]), True)
    answer(win, True)
    win.do_install()
    ui.settle(app, win)
    assert "administrator rights were not granted" in win.status.text() and win.status.property("kind") == "error"


def test_demo_mode_never_installs(tmp_path, windows, runner, monkeypatch):
    monkeypatch.setattr(engine, "apply", lambda *a, **k: pytest.fail("demo must not install"))
    app, win = ui.create(engine.Context(demo=True), tmp_path)
    upd = make_update("Wifi", PARTIAL_CHECKS)
    win.model.load([upd.device], [upd])
    win.model.set_selected(0, True)
    win.do_install()
    assert "Demo: nothing was installed" in win.status.text() and not win.log.isHidden()
    win.close()


# ----------------------------------------------------------------- themes
from ui import settings  # noqa: E402


def badge_colours(win, update):
    image = win.view.viewport().grab().toImage()
    r = win.view.visualRect(win.model.index(row_of(win, update), COL_VERIFY))
    return {image.pixelColor(x, y).name() for x in range(r.left(), r.right()) for y in range(r.top(), r.bottom())}


def test_matrix_uses_the_bundled_pixel_font(window):
    assert "VT323" in theme.register_fonts() or theme._fonts_registered
    assert theme.current().name == "matrix" and theme.family() == "VT323" and theme.scale() > 1
    assert theme.current().fonts[:6] == ("VT323", "Fixedsys Excelsior", "PxPlus IBM VGA8", "Terminus",
                                         "Courier New", "Consolas")
    assert (theme.FONT_DIR / "VT323-Regular.ttf").is_file() and (theme.FONT_DIR / "VT323-OFL.txt").is_file()
    assert "font-family: 'VT323'" in QApplication_instance().styleSheet()


def QApplication_instance():
    from PySide6.QtWidgets import QApplication
    return QApplication.instance()


def test_theme_toggle_switches_in_place_and_is_remembered(window):
    app, win, ups = window
    assert win.btn_theme.text() == "[ MATRIX ]" and win.btn_log.text() == "LOG"
    assert "#00ff66" in badge_colours(win, ups["full"])
    QTest.mouseClick(win.btn_theme, Qt.LeftButton)
    app.processEvents()
    t = theme.current()
    assert t.name == "clean" and win.btn_theme.text() == "[ CLEAN ]" and win.btn_rescan.text() == "Rescan"
    assert t.badges["full"][0].lower() in badge_colours(win, ups["full"])     # delegates repainted, no restart
    assert "#00ff66" not in badge_colours(win, ups["full"])
    assert theme.family() != "VT323" and "VT323" not in QApplication_instance().styleSheet()
    assert win.view.verticalHeader().defaultSectionSize() == t.row_height
    assert not win.status.text().startswith(">")                              # no terminal prompt in Clean
    assert settings.load() == {"theme": "clean"} and settings.user_file().is_file()
    QTest.mouseClick(win.btn_theme, Qt.LeftButton)
    assert theme.current().name == "matrix" and win.status.text().startswith("> ")
    assert settings.load() == {"theme": "matrix"}


def test_remembered_theme_and_cli_override(tmp_path, windows, runner):
    settings.save(theme="clean")
    app, win = ui.create(engine.Context(manifest={"packages": []}), tmp_path)
    assert theme.current().name == "clean" and win.btn_theme.text() == "[ CLEAN ]"
    win.close()
    app, win = ui.create(engine.Context(manifest={"packages": []}), tmp_path, theme="matrix")
    assert theme.current().name == "matrix"
    assert settings.load()["theme"] == "clean"                  # --theme is for one launch, not saved
    win.close()


def test_open_popover_is_closed_on_theme_change(window):
    app, win, ups = window
    win.open_details(win.model.index(row_of(win, ups["partial"]), COL_VERIFY))
    assert win.popover is not None
    win.toggle_theme()
    assert win.popover is None


def test_clean_theme_is_metallic_monochrome():
    assert theme.resolve("clean") is theme.CLEAN_THEME and theme.resolve("matrix") is theme.MATRIX_THEME
    t = theme.set_current("clean")
    try:
        c = t.colors
        assert (c["BG"], c["SURFACE"], c["BORDER"], c["BORDER_HOVER"]) == ("#0D0F12", "#15181E", "#2B313C", "#4A5364")
        assert (c["TEXT"], c["MUTED"], c["SLATE"]) == ("#F4F6F9", "#8C95A4", "#565E6B")
        sheet = theme.stylesheet()
        # gradient header, brushed-platinum primary button with dark bold text and a top highlight
        assert "stop:0 #1D2129, stop:1 #14171D" in sheet
        primary = sheet[sheet.rindex("QPushButton#primary {"):]
        assert "stop:0 #E8ECF2, stop:1 #C2C9D4" in primary and "color: #0D0F12" in primary
        assert "font-weight: 700" in primary and "border-top: 1px solid #FFFFFF" in primary
        assert "Segoe UI" in t.fonts and "VT323" not in sheet
        b = t.badges
        assert b["accent"][0] == "#E4E8EF" and b["accent"][4] == "#232832"          # TO UPDATE
        assert b["uptodate"][0] == "#565E6B"                                       # UP TO DATE
        assert b["full"][:2] == ("#F4F6F9", "#F4F6F9") and b["full"][5] == "check"  # FULL, outlined, tick
        assert b["partial"][1] == "#C8B99A" and c["AMBER"] == "#C8B99A"            # PARTIAL and its (?)
        assert b["none"][0] == "#D47A7A"                                           # NONE
        assert theme.badge_text("To update") == "TO UPDATE"
    finally:
        theme.set_current("matrix")
    with pytest.raises(ValueError):
        theme.set_current("neon")
