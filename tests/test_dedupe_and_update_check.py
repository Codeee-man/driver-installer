"""Identical devices shown once (16 logical CPUs -> one row x16), and the startup check for a
newer Driver Installer release (core) with its "Update available" header button (GUI)."""
from __future__ import annotations

import io
import json
import os
from pathlib import Path

import pytest

import cli
from core import common, engine, scanner_win, updates
from core.model import Device, dedupe_devices

FIXTURES = Path(__file__).parent / "fixtures"
CPU = "12th Gen Intel(R) Core(TM) i5-12500H"
CPU_HWID = f"ACPI\\GenuineIntel_-_Intel64_Family_6_Model_154_-_{CPU}"


def cpu_rows(count=16, version="10.0.26100.9818"):
    """What WMI reports for a 16-thread CPU: one PnP entity per logical processor, each with its
    own instance path (..\\_0 .. \\_15) and the same hardware IDs, INF and driver version."""
    entities, signed = [], []
    for n in range(count):
        pnp = f"ACPI\\GENUINEINTEL_-_INTEL64_FAMILY_6_MODEL_154_-_12TH_GEN_INTEL(R)_CORE(TM)_I5-12500H\\_{n}"
        entities.append({"Name": CPU, "PNPDeviceID": pnp, "PNPClass": "Processor", "Manufacturer": "Intel",
                         "Service": "intelppm", "ClassGuid": "{50127dc3-0f36-415e-a6cc-4cb3be910b65}",
                         "HardwareID": [CPU_HWID, "*GenuineIntel_-_Intel64_Family_6_Model_154",
                                        "ACPI\\GenuineIntel_-_Intel64_Family_6", "*GenuineIntel"],
                         "ConfigManagerErrorCode": 0, "Present": True})
        signed.append({"DeviceID": pnp, "DeviceName": CPU, "DriverVersion": version, "InfName": "cpu.inf",
                       "DriverDate": "/Date(1529452800000)/", "DriverProviderName": "Microsoft", "IsSigned": True})
    return entities, signed


# ------------------------------------------------------------ deduplication
def test_sixteen_logical_cpus_become_one_device_with_every_instance():
    entities, signed = cpu_rows()
    devices = scanner_win.build_devices(entities, signed, [])
    assert len(devices) == 16                                       # what WMI says
    (cpu,) = dedupe_devices(devices)
    assert cpu.name == CPU and cpu.count == 16 and cpu.driver_version == "10.0.26100.9818"
    assert len(cpu.instances) == 16 and cpu.instances[0].endswith("\\_0") and cpu.instances[-1].endswith("\\_15")
    assert cpu.address == cpu.instances[0]
    # every instance's IDs stay attached, so Windows Update / Catalog matching still sees them
    raws = {h for h in cpu.hardware_ids if h.startswith("raw:")}
    assert {"raw:" + i.lower() for i in cpu.instances} <= raws
    assert "raw:" + CPU_HWID.lower() in raws
    assert len(cpu.hardware_ids) == len(set(cpu.hardware_ids))      # no duplicates in the union


def test_only_truly_identical_devices_are_merged():
    entities, signed = cpu_rows(4)
    signed[3]["DriverVersion"] = "10.0.26100.1"                      # another installed version
    entities[2]["ConfigManagerErrorCode"] = 43                       # one instance has a problem
    devices = scanner_win.build_devices(entities, signed, [])
    out = dedupe_devices(devices)
    assert [d.count for d in out] == [2, 1, 1]
    assert out[1].notes[-1].startswith("problem code 43") and out[2].driver_version == "10.0.26100.1"
    # same name but another model, another INF, or a fwupd device: never merged
    a = Device("USB Hub", kind="usb", hardware_ids=["usb:05e3:0610"], address="1-1", driver_version="1")
    b = Device("USB Hub", kind="usb", hardware_ids=["usb:05e3:0626"], address="2-1", driver_version="1")
    c = Device("USB Hub", kind="usb", hardware_ids=["usb:05e3:0610"], address="3-1", driver_version="1")
    fw1 = Device("UEFI", kind="fwupd", hardware_ids=["fwupd:x"], address="abc", driver_version="1")
    fw2 = Device("UEFI", kind="fwupd", hardware_ids=["fwupd:x"], address="def", driver_version="1")
    nothing = [Device("Thing", address=f"t{n}") for n in range(2)]   # no model ID and no INF to compare
    out = dedupe_devices([a, b, c, fw1, fw2, *nothing])
    assert [(d.hardware_ids[0], d.count) for d in out[:2]] == [("usb:05e3:0610", 2), ("usb:05e3:0626", 1)]
    assert out[0].instances == ["1-1", "3-1"]
    assert len(out) == 6 and all(d.count == 1 for d in out[1:])
    assert Device("x").count == 1                                     # not deduplicated yet: one device


def test_names_are_compared_normalised():
    a = Device("Intel  Core i5", inf="cpu.inf", address="a", hardware_ids=["raw:a", "raw:cpu"], driver_version="1")
    b = Device("intel core i5 ", inf="CPU.INF", address="b", hardware_ids=["raw:b", "raw:cpu"], driver_version="1")
    (merged,) = dedupe_devices([a, b])
    assert merged.name == "Intel  Core i5" and merged.instances == ["a", "b"]


@pytest.fixture
def wmi_with_cpus(tmp_path, monkeypatch, windows, runner):
    """The standard WMI fixture PC plus a 16-thread CPU."""
    wmi = tmp_path / "wmi"
    wmi.mkdir()
    entities, signed = cpu_rows()
    for name, extra in (("Win32_PnPEntity", entities), ("Win32_PnPSignedDriver", signed), ("Win32_SystemDriver", [])):
        rows = json.loads((FIXTURES / "wmi" / f"{name}.json").read_text(encoding="utf-8")) + extra
        (wmi / f"{name}.json").write_text(json.dumps(rows), encoding="utf-8")
    monkeypatch.setattr(scanner_win, "default_source", lambda: scanner_win.FixtureWmiSource(wmi))


def test_scan_and_cli_show_one_row_with_the_count(wmi_with_cpus, as_user, capsys):
    devices, _ = engine.scan()
    cpus = [d for d in devices if d.name == CPU]
    assert len(cpus) == 1 and cpus[0].count == 16
    assert len(devices) == 6                                        # 5 fixture devices + 1 CPU row
    log = [json.loads(line) for line in common.audit_log().path.read_text().splitlines()]
    dedup = next(r for r in log if r["event"] == "scan.deduplicated")
    assert dedup["data"]["instances"] == 21 and dedup["data"]["devices"] == 6
    assert dedup["data"]["merged"] == [f"{CPU} x16"]
    assert cli.main(["scan"]) == 0
    out = capsys.readouterr().out
    assert [line for line in out.splitlines() if CPU in line][0].startswith(f"{CPU} x16")
    assert out.count(CPU) == 1 and "6 devices" in out
    assert cli.main(["scan", "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    (cpu,) = [d for d in report["devices"] if d["name"] == CPU]
    assert len(cpu["instances"]) == 16


def test_gui_shows_one_row_with_a_subtle_count(tmp_path, windows, runner):
    pytest.importorskip("PySide6")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    import gui
    from PySide6.QtCore import Qt
    from ui.models import COL_DEVICE, CountRole
    entities, signed = cpu_rows()
    (cpu,) = dedupe_devices(scanner_win.build_devices(entities, signed, []))
    app, win = gui.create(engine.Context(manifest={"packages": []}), tmp_path)
    try:
        win.model.load([cpu, Device("Audio", driver_version="6.0")], [])
        names = [win.model.index(r, COL_DEVICE).data(Qt.DisplayRole) for r in range(win.model.rowCount())]
        assert names.count(CPU) == 1
        index = win.model.index(names.index(CPU), COL_DEVICE)
        assert index.data(CountRole) == 16 and index.data(Qt.DisplayRole) == CPU          # name stays clean
        assert "16 identical devices" in index.data(Qt.ToolTipRole)
        assert index.data(Qt.AccessibleTextRole) == f"{CPU}, 16 identical devices"
        assert win.model.index(names.index("Audio"), COL_DEVICE).data(CountRole) == 1
        win.resize(1000, 400)
        win.show()
        app.processEvents()
        assert not win.view.viewport().grab().isNull()                                      # paints the ×16 tag
    finally:
        win.close()


# ------------------------------------------------------------ update check
class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def opener_for(payload=None, error: Exception | None = None, seen: list | None = None):
    def opener(request, timeout=None):
        if seen is not None:
            seen.append((request, timeout))
        if error is not None:
            raise error
        return FakeResponse(json.dumps(payload).encode())
    return opener


def test_latest_release_is_compared_with_the_running_version():
    seen = []
    assert updates.update_available(opener_for({"tag_name": "v1.2.0"}, seen=seen), running="1.1.5")
    request, timeout = seen[0]
    assert request.full_url == "https://api.github.com/repos/Codeee-man/driver-installer/releases/latest"
    assert timeout == 3.0 and request.get_header("Accept") == "application/vnd.github+json"
    assert request.get_header("User-agent").startswith(common.APP)
    assert not updates.update_available(opener_for({"tag_name": "v1.1.5"}), running="1.1.5")
    assert not updates.update_available(opener_for({"tag_name": "v1.1.4"}), running="1.1.5")
    assert updates.update_available(opener_for({"tag_name": "v1.1.6"}), running="1.1.5+gitabc1234")
    assert updates.is_newer("v2.0", "1.9.9") and not updates.is_newer(None, "1.0") and not updates.is_newer("latest", "1.0")


@pytest.mark.parametrize("error, payload", [
    (OSError("offline"), None),
    (__import__("urllib.error").error.HTTPError(updates.LATEST_API, 403, "rate limit exceeded", {}, None), None),
    (TimeoutError("timed out"), None),
    (None, ["not", "an", "object"]),
    (None, {"message": "Not Found"}),
    (None, {"tag_name": 12}),
])
def test_any_failure_is_silent_and_means_no_update(error, payload):
    assert updates.latest_tag(opener_for(payload, error)) is None
    assert updates.update_available(opener_for(payload, error), running="0.1") is False


def test_tests_never_reach_github():
    with pytest.raises(OSError):
        updates.OPENER(updates.LATEST_API)


@pytest.fixture
def gui_window(tmp_path, windows, runner):
    pytest.importorskip("PySide6")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    import gui
    app, win = gui.create(engine.Context(manifest={"packages": []}), tmp_path)
    win.show()
    app.processEvents()
    yield app, win
    win.close()


def wait_for(app, win, timeout=5.0):
    import time
    deadline = time.monotonic() + timeout
    while win.update_check.isRunning() and time.monotonic() < deadline:
        app.processEvents()
        time.sleep(0.005)
    for _ in range(5):
        app.processEvents()


def test_update_button_appears_only_when_a_newer_release_exists(gui_window, monkeypatch):
    app, win = gui_window
    assert win.btn_update.isHidden()                                    # nothing known yet: no button
    monkeypatch.setattr(updates, "OPENER", opener_for({"tag_name": "v99.0.0"}))
    assert win.start_update_check() is not None
    wait_for(app, win)
    assert win.btn_update.isVisible()
    assert win.btn_update.objectName() == "updateButton" and win.btn_update.accessibleName() == "Update available"
    text = win.btn_update.text()
    assert text.lower() == "update available" and not any(ch.isdigit() for ch in text)   # no version number
    assert win.start_update_check() is None                             # once per start


def test_no_button_when_up_to_date_or_offline(gui_window, monkeypatch):
    app, win = gui_window
    monkeypatch.setattr(updates, "OPENER", opener_for({"tag_name": "v" + common.VERSION}))
    win.start_update_check()
    wait_for(app, win)
    assert win.btn_update.isHidden()
    win.update_check = None
    monkeypatch.setattr(updates, "OPENER", opener_for(error=OSError("offline")))
    win.start_update_check()
    wait_for(app, win)
    assert win.btn_update.isHidden() and "Ready." in win.status.text()  # silent: no popup, no message


def test_update_check_respects_the_setting(gui_window, monkeypatch):
    from ui import settings
    app, win = gui_window
    calls = []
    monkeypatch.setattr(updates, "OPENER", lambda *a, **k: calls.append(a) or opener_for({"tag_name": "v99"})(*a, **k))
    settings.save(check_updates=False)
    assert win.start_update_check() is None and win.update_check is None
    app.processEvents()
    assert calls == [] and win.btn_update.isHidden()


def test_update_check_does_not_block_the_window(gui_window, monkeypatch):
    import threading
    app, win = gui_window
    release = threading.Event()

    def slow(request, timeout=None):
        release.wait(5)
        return FakeResponse(b'{"tag_name": "v99.0"}')
    monkeypatch.setattr(updates, "OPENER", slow)
    win.start_update_check()
    app.processEvents()
    assert win.update_check.isRunning() and not win.busy                # the window stays usable
    assert win.btn_rescan.isEnabled() and win.btn_update.isHidden()
    release.set()
    wait_for(app, win)
    assert win.btn_update.isVisible()


def test_clicking_update_available_opens_the_release_page(gui_window, monkeypatch):
    from PySide6.QtCore import Qt
    from PySide6.QtGui import QDesktopServices
    from PySide6.QtTest import QTest
    app, win = gui_window
    opened = []
    monkeypatch.setattr(QDesktopServices, "openUrl", lambda url: opened.append(url.toString()) or True)
    win.on_update_result(True)
    app.processEvents()
    QTest.mouseClick(win.btn_update, Qt.LeftButton)
    assert opened == ["https://github.com/Codeee-man/driver-installer/releases/latest"]


def test_run_starts_the_update_check_but_screenshots_do_not(tmp_path, windows, runner, monkeypatch):
    pytest.importorskip("PySide6")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from ui import main_window
    started = []
    monkeypatch.setattr(main_window.MainWindow, "start_update_check", lambda self: started.append(self))
    monkeypatch.setattr(main_window.MainWindow, "start_scan", lambda self: None)
    shot = tmp_path / "shot.png"
    assert main_window.run(engine.Context(manifest={"packages": []}), tmp_path, str(shot)) == 0
    assert shot.is_file() and started == []
    from PySide6.QtWidgets import QApplication
    monkeypatch.setattr(QApplication, "exec", lambda self: 0)
    assert main_window.run(engine.Context(manifest={"packages": []}), tmp_path) == 0
    assert len(started) == 1
