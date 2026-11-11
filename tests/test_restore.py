"""Restore-point abstraction: System Restore, Timeshift, snapper."""
import json

from conftest import RESTORE_CREATED, RESTORE_DISABLED
from core import common, restore


def test_windows_restore_point_created(runner, windows):
    runner.on("powershell", common.Result(0, RESTORE_CREATED))
    res = restore.create()
    assert res.ok and res.status == "created" and res.ident == "42" and res.tool == "system-restore"
    assert runner.calls[0][2]["SD_DESC"] == "Pre-Driver-Installer Update"
    assert "DEVICE_DRIVER_INSTALL" in restore._WINDOWS_PS and "Checkpoint-Computer" in restore._WINDOWS_PS


def test_windows_recent_restore_point_is_reused(runner, windows):
    runner.on("powershell", common.Result(0, json.dumps(
        {"Before": 42, "After": 42, "Warning": "A new system restore point cannot be created because one has "
                                               "already been created within the past 1440 minutes.", "Error": None})))
    res = restore.create()
    assert res.ok and res.status == "existing"


def test_windows_system_restore_disabled_fails_gracefully(runner, windows):
    runner.on("powershell", common.Result(0, RESTORE_DISABLED))
    res = restore.create()
    assert not res.ok and res.status == "failed"
    assert "disabled" in res.detail and "System Protection" in res.detail      # tells the user what to do


def test_windows_silent_no_op_is_not_reported_as_success(runner, windows):
    runner.on("powershell", common.Result(0, json.dumps({"Before": 7, "After": 7, "Warning": "", "Error": None})))
    assert restore.create().status == "failed"
    runner.on("powershell", common.Result(1, "", "boom"))
    assert restore.create().status == "failed"
    runner.available.discard("powershell")
    assert restore.create().status == "failed"


def test_linux_prefers_timeshift(runner, linux):
    runner.available = {"timeshift", "snapper"}
    res = restore.create()
    assert res.ok and res.tool == "timeshift" and restore.detect() == "timeshift"
    assert runner.ran("timeshift") == [["--create", "--comments", "Pre-Driver-Installer Update", "--tags", "O", "--scripted"]]
    assert runner.ran("snapper") == []


def test_linux_snapper_when_no_timeshift(runner, linux):
    runner.available = {"snapper"}
    runner.on("snapper", common.Result(0, "137\n"))
    res = restore.create()
    assert res.ok and res.tool == "snapper" and res.ident == "137"
    args = runner.ran("snapper")[0]
    assert args[:3] == ["-c", "root", "create"] and args[-2:] == ["--description", "Pre-Driver-Installer Update"]


def test_linux_falls_back_to_snapper_when_timeshift_fails(runner, linux):
    runner.available = {"timeshift", "snapper"}
    runner.on("timeshift", common.Result(1, "", "E: No snapshot device configured"))
    assert restore.create().tool == "snapper"


def test_linux_tool_present_but_failing_is_a_failure(runner, linux):
    runner.available = {"timeshift"}
    runner.on("timeshift", common.Result(1, "", "E: Not enough disk space"))
    res = restore.create()
    assert res.status == "failed" and "Not enough disk space" in res.detail


def test_linux_without_any_tool_is_unavailable_and_logged_as_warning(runner, linux, tmp_path):
    runner.available = set()
    res = restore.create()
    assert res.status == "unavailable" and not res.ok and restore.detect() is None
    events = [json.loads(line)["event"] for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
    assert "restore.warning" in events


def test_dry_run_runs_nothing(runner, linux):
    runner.available = {"timeshift"}
    res = restore.create(dry_run=True)
    assert res.status == "dry-run" and res.detail.startswith("timeshift --create") and runner.calls == []
