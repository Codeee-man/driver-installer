"""GUI install flow, driven headlessly. engine.apply is replaced, so nothing is installed."""
import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6")

import gui  # noqa: E402
from core import engine  # noqa: E402
from core.common import ElevationError  # noqa: E402
from core.model import Device, Update  # noqa: E402
from test_scanner_win import _pkg  # noqa: E402


@pytest.fixture
def window(tmp_path, windows, runner):
    app, win = gui.create(engine.Context(manifest={"packages": []}), tmp_path)
    dev = Device("Intel Wi-Fi", hardware_ids=["pci:8086:2725"], driver_version="22.250.1.2")
    win.devices = [dev]
    win.updates = [Update(dev, "Intel Wi-Fi driver", "22.250.1.2", "23.60.1.2", "vendor", "a" * 64,
                          _pkg("intel.wifi", "pci:8086:2725", "23.60.1.2"), "verified", "SHA-256 OK", "/q/a.zip")]
    win.refresh()
    win.questions = []
    yield app, win
    win.close()


def answer(win, *answers):
    replies = iter(answers)

    def ask(title, text, details, accept_label):
        win.questions.append((title, details))
        return next(replies)
    win.ask = ask


def test_install_needs_confirmation_and_cancel_installs_nothing(window, monkeypatch):
    app, win = window
    monkeypatch.setattr(engine, "apply", lambda *a, **k: pytest.fail("must not install without confirmation"))
    answer(win, False)
    win.do_install()
    gui.settle(app, win)
    assert win.status.text() == "Cancelled. Nothing was installed."
    title, details = win.questions[0]
    assert title == "Install drivers" and "22.250.1.2 -> 23.60.1.2" in details and "pnputil /add-driver" in details


def test_confirmed_install_shows_result_per_row(window, monkeypatch):
    app, win = window
    monkeypatch.setattr(engine, "apply", lambda todo, ctx, **kw: {
        "status": "ok", "reboot_required": True, "snapshot": {"status": "created"},
        "items": [{"id": "intel.wifi", "name": "Intel Wi-Fi driver", "status": "reboot-required",
                   "detail": "driver installed; restart to finish", "rc": 3010, "commands": []}]})
    answer(win, True)
    win.do_install()
    gui.settle(app, win)
    assert win.status.text() == "1 installed, 0 failed. Restart to finish."
    assert win.table.item(0, 6).text().startswith("reboot-required")
    assert win.banner.property("kind") == "ok"


def test_snapshot_failure_asks_again_before_continuing(window, monkeypatch):
    app, win = window
    calls = []

    def fake_apply(todo, ctx, allow_without_snapshot=False, allow_without_blocklist=False):
        calls.append(allow_without_snapshot)
        if not allow_without_snapshot:
            return {"status": "snapshot_failed", "snapshot_required": False, "items": [],
                    "detail": "no restore point: System Restore is disabled. Nothing was installed."}
        return {"status": "ok", "items": [{"id": "intel.wifi", "name": "x", "status": "installed", "detail": "installed"}]}
    monkeypatch.setattr(engine, "apply", fake_apply)
    answer(win, True, False)                       # install: yes; continue without restore point: no
    win.do_install()
    gui.settle(app, win)
    assert calls == [False] and win.questions[1][0] == "No restore point"
    assert win.status.text() == "Nothing was installed." and "System Restore is disabled" in win.banner.text()
    answer(win, True, True)                        # this time the user agrees
    win.do_install()
    gui.settle(app, win)
    gui.settle(app, win)
    assert calls == [False, False, True] and win.status.text() == "1 installed, 0 failed."


def test_declined_elevation_is_reported_not_swallowed(window, monkeypatch):
    app, win = window

    def declined(*a, **k):
        raise ElevationError("the UAC prompt was declined")
    monkeypatch.setattr(engine, "apply", declined)
    answer(win, True)
    win.do_install()
    gui.settle(app, win)
    assert "Administrator rights were not granted" in win.banner.text()
    assert win.status.text() == "Nothing was installed."


def test_security_alert_is_shown_and_nothing_else_is_offered(window, monkeypatch):
    app, win = window
    monkeypatch.setattr(engine, "apply", lambda todo, ctx, **kw: {
        "status": "security_alert", "items": [], "alerts": ["intel.wifi"],
        "detail": "SECURITY ALERT: evil.sys is a known malicious (LOLDrivers aaaa, sha256 ff). Installation aborted."})
    answer(win, True)
    win.do_install()
    gui.settle(app, win)
    assert win.status.text() == "BLOCKED. Nothing was installed."
    assert "SECURITY ALERT: evil.sys" in win.banner.text() and win.banner.property("kind") == "error"
    assert len(win.questions) == 1                      # no "continue anyway" question for a blocklist hit


def test_unavailable_blocklist_asks_before_continuing_unchecked(window, monkeypatch):
    app, win = window
    calls = []

    def fake_apply(todo, ctx, allow_without_snapshot=False, allow_without_blocklist=False):
        calls.append((allow_without_snapshot, allow_without_blocklist))
        if not allow_without_blocklist:
            return {"status": "blocklist_unavailable", "items": [],
                    "detail": "the LOLDrivers blocklist could not be loaded: timeout. Nothing was installed."}
        return {"status": "ok", "items": [{"id": "intel.wifi", "name": "x", "status": "installed", "detail": "ok"}]}
    monkeypatch.setattr(engine, "apply", fake_apply)
    answer(win, True, False)
    win.do_install()
    gui.settle(app, win)
    assert calls == [(False, False)] and win.questions[1][0] == "Vulnerable-driver check unavailable"
    assert win.status.text() == "Nothing was installed."
    answer(win, True, True)
    win.do_install()
    gui.settle(app, win)
    gui.settle(app, win)
    assert calls[-1] == (False, True) and win.status.text() == "1 installed, 0 failed."
