"""Subcommands (scan / check / update), --notify, helper path selection, helper entry point."""
import json
import os
import stat
import sys
from pathlib import Path

import pytest

import cli
import demo
import helper_main
from core import common, elevation, engine
from core.common import ElevationError
from core.model import Device
from test_apply_flow import win_env  # noqa: F401  (fixture)


def gpu_manifest(pin, tmp_path, version="550.120"):
    pkg = {"id": "distro.nvidia.driver", "name": "NVIDIA driver <550>", "vendor": "NVIDIA", "category": "driver",
           "version": version, "platform": {"os": "linux", "arch": ["x86_64"]}, "hardware_ids": ["pci:10de:2684"],
           "install": {"method": "package-manager", "package_name": "nvidia-driver-550", "reboot_required": True},
           "upstream": {"source": "distro", "reference_url": "https://example.invalid/nvidia"}}
    raw, sig = pin(demo.manifest_shell([pkg]))
    (tmp_path / "m.json").write_bytes(raw)
    (tmp_path / "m.json.sig").write_bytes(sig)
    return ["--manifest", str(tmp_path / "m.json")]


@pytest.fixture
def linux_box(runner, linux, monkeypatch):
    """A Linux machine with one GPU on driver 535.1 and one firmware device fwupd has an update for."""
    runner.available = set()
    gpu = Device("GeForce RTX 4090", kind="pci", hardware_ids=["pci:10de:2684"], driver="nvidia",
                 driver_version="535.1")
    ssd = Device("NVMe SSD", kind="fwupd", hardware_ids=["fwupd:x"], driver_version="1.0", address="c" * 40)
    box = {"devices": [gpu, ssd], "upgrades": {}}
    monkeypatch.setattr(engine, "scan", lambda: (box["devices"], box["upgrades"]))
    return box


# -------------------------------------------------------------------- scan
def test_scan_prints_table_of_hardware_against_manifest(win_env, as_user, capsys):
    assert cli.main(["scan", *win_env.publish()]) == 0
    out = capsys.readouterr().out
    assert out.splitlines()[0].startswith("DEVICE") and "-+-" in out.splitlines()[1]
    row = next(line for line in out.splitlines() if "AX210" in line)
    assert [c.strip() for c in row.split("|")][1:] == ["22.250.1.2", "23.60.1.2", "UPDATE", "intel.wifi.ax210"]
    assert "NVIDIA GeForce RTX 4070" in out and "5 devices, 1 update(s) available." in out
    assert win_env.runner.ran("pnputil") == []


def test_scan_json_and_no_manifest(win_env, as_user, capsys):
    assert cli.main(["scan", "--json", *win_env.publish()]) == 0
    report = json.loads(capsys.readouterr().out)
    assert len(report["devices"]) == 5 and report["updates"][0]["id"] == "intel.wifi.ax210"
    assert cli.main(["scan"]) == 0
    assert "No manifest loaded" in capsys.readouterr().out


# ------------------------------------------------------------------- check
def test_check_exit_codes(linux_box, pin, tmp_path, capsys):
    assert cli.main(["check"]) == 0                                       # nothing to compare against
    assert capsys.readouterr().out.strip() == "Up to date."
    assert cli.main(["check", *gpu_manifest(pin, tmp_path)]) == 1          # 535.1 -> 550.120
    assert "535.1 -> 550.120" in capsys.readouterr().out
    assert cli.main(["check", "--quiet", *gpu_manifest(pin, tmp_path, version="535.1")]) == 0
    assert capsys.readouterr().out == ""
    linux_box["upgrades"] = {"c" * 40: {"Version": "1.1", "Name": "NVMe firmware"}}
    assert cli.main(["check", "--json"]) == 1                              # fwupd update, no manifest needed
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "updates-available" and report["updates"][0]["id"] == "fwupd:" + "c" * 40


def test_check_errors_use_codes_2_and_above(linux_box, pin, tmp_path, monkeypatch, capsys):
    args = gpu_manifest(pin, tmp_path)
    (tmp_path / "m.json").write_bytes((tmp_path / "m.json").read_bytes().replace(b"550.120", b"999.999"))
    assert cli.main(["check", *args]) == 2                                 # tampered manifest
    assert "REFUSED" in capsys.readouterr().err
    assert cli.main(["check", "--manifest", str(tmp_path / "missing.json")]) == 3
    assert cli.main(["check", "--manifest", "http://example.invalid/m.json"]) == 2     # plain http refused

    def broken():
        raise common.InstallError("scanner exploded")
    monkeypatch.setattr(engine, "scan", broken)
    assert cli.main(["check"]) == 3


def test_notify_only_when_updates_exist(linux_box, runner, pin, tmp_path):
    runner.available = {"notify-send"}
    assert cli.main(["check", "--notify", "--quiet"]) == 0
    assert runner.ran("notify-send") == []
    assert cli.main(["check", "--notify", "--quiet", *gpu_manifest(pin, tmp_path)]) == 1
    (args,) = runner.ran("notify-send")
    assert args[-2] == "1 driver/firmware update available"
    assert "NVIDIA driver &lt;550&gt;" in args[-1] and args[-3] == "--"    # markup escaped, options terminated


def test_notify_without_notify_send_is_not_an_error(linux_box, runner, pin, tmp_path):
    assert cli.main(["check", "--notify", *gpu_manifest(pin, tmp_path)]) == 1
    assert runner.calls == []


def test_manifest_from_https_url(linux_box, pin, tmp_path, loopback, capsys):
    args = gpu_manifest(pin, tmp_path)
    server, base = demo.serve(tmp_path)
    try:
        assert cli.main(["check", "--manifest", f"{base}/m.json"]) == 1
        (tmp_path / "m.json.sig").write_bytes(b"AAAA")
        assert cli.main(["check", "--manifest", f"{base}/m.json"]) == 2
    finally:
        server.shutdown()
    assert args


# ------------------------------------------------------------------ update
def test_update_needs_all_or_ids(win_env, as_user):
    with pytest.raises(SystemExit) as exc:
        cli.main(["update", *win_env.publish()])
    assert exc.value.code == 2


def test_update_yes_without_apply_is_still_a_dry_run(win_env, as_user, monkeypatch, capsys):
    monkeypatch.setattr(elevation, "run_elevated", lambda *a, **k: pytest.fail("dry run must not elevate"))
    assert cli.main(["update", "--all", "-y", *win_env.publish()]) == 0
    out = capsys.readouterr().out
    assert "DRY RUN - nothing was installed. -y has no effect without --apply." in out
    assert win_env.runner.ran("pnputil") == []


def test_update_all_apply_yes_is_non_interactive(win_env, as_user, monkeypatch, capsys):
    monkeypatch.setattr(elevation, "run_elevated", win_env.helper_runs_elevated)
    monkeypatch.setattr("builtins.input", lambda prompt: pytest.fail("must not prompt with -y"))
    assert cli.main(["update", "--all", "--apply", "-y", *win_env.publish()]) == 0
    assert len(win_env.runner.ran("pnputil")) == 1 and "installed" in capsys.readouterr().out


def test_update_by_id(win_env, as_user, capsys):
    assert cli.main(["update", "intel.wifi.ax210", *win_env.publish()]) == 0
    assert "Intel Wi-Fi 6E AX210 driver" in capsys.readouterr().out
    assert cli.main(["update", "no.such.package", *win_env.publish()]) == 2
    err = capsys.readouterr().err
    assert "No such update: no.such.package" in err and "intel.wifi.ax210" in err


def test_root_runs_unattended_update_without_any_prompt(linux_box, runner, pin, tmp_path, as_admin, monkeypatch):
    """`driver-installer update --all --apply -y` from a root shell or root cron job."""
    runner.available = {"apt-get", "timeshift"}
    monkeypatch.setattr(elevation, "run_elevated", lambda *a, **k: pytest.fail("root needs no elevation"))
    assert cli.main(["update", "--all", "--apply", "-y", *gpu_manifest(pin, tmp_path)]) == 0
    assert runner.programs() == ["timeshift", "apt-get"]


# ------------------------------------------------------------- helper path
def test_uninstalled_helper_falls_back_to_repo_copy_with_a_warning(tmp_path, linux, caplog):
    argv = elevation.helper_command(tmp_path / "plan.json")
    assert argv == [sys.executable, "-I", str(elevation.REPO_HELPER), "--apply-plan", str(tmp_path / "plan.json")]
    assert elevation.REPO_HELPER.name == "helper_main.py" and elevation.REPO_HELPER.is_file()
    assert "running un-installed" in caplog.text and "tools/install_helper.sh" in caplog.text
    events = [json.loads(line)["event"] for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
    assert "elevation.warning" in events


def test_installed_helper_is_preferred(tmp_path, linux, monkeypatch, caplog):
    helper = tmp_path / "bin" / "driver-installer-helper"
    helper.parent.mkdir()
    helper.write_text("#!/bin/sh\n")
    monkeypatch.setattr(elevation, "HELPER_LINUX", str(helper))
    monkeypatch.setattr(elevation, "_admin_only", lambda path: True)
    assert elevation.helper_command("/p/plan.json") == [str(helper), "--apply-plan", "/p/plan.json"]
    assert "un-installed" not in caplog.text
    assert engine.helper_argv(Path("/p/plan.json"))[0] == str(helper)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX ownership and permission bits")
def test_installed_helper_that_others_can_modify_is_refused_not_bypassed(tmp_path, linux, monkeypatch):
    helper = tmp_path / "driver-installer-helper"
    helper.write_text("#!/bin/sh\n")
    os.chmod(helper, 0o777)
    monkeypatch.setattr(elevation, "HELPER_LINUX", str(helper))
    with pytest.raises(ElevationError, match="can be modified by non-administrators"):
        elevation.helper_command("/p/plan.json")
    os.chmod(helper, 0o755)
    os.chmod(tmp_path, 0o777)                              # safe file in a directory anyone can write
    with pytest.raises(ElevationError):
        elevation.helper_command("/p/plan.json")
    os.chmod(tmp_path, 0o755)
    if os.geteuid() == 0:                                   # root-owned and not writable by others: accepted
        assert elevation.installed_helper() == str(helper)
    assert stat.S_IMODE(os.stat(helper).st_mode) == 0o755


def test_windows_helper_exe_in_program_files(tmp_path, windows, monkeypatch, caplog):
    assert elevation.helper_command("plan.json")[1:3] == ["-I", str(elevation.REPO_HELPER)]
    assert "DriverInstaller-Setup.exe" in caplog.text
    monkeypatch.setattr(elevation.ntpath, "join", os.path.join)        # POSIX test host
    exe = tmp_path / "ProgramFiles" / "driver-installer" / "helper.exe"
    exe.parent.mkdir(parents=True)
    exe.write_bytes(b"MZ")
    assert elevation.helper_command("plan.json") == [str(exe), "--apply-plan", "plan.json"]


# ------------------------------------------------------- helper entry point
@pytest.mark.parametrize("argv", [
    [], ["--apply-plan"], ["plan.json"], ["--apply-plan", "p.json", "--log", "/etc/passwd"],
    ["--manifest", "m.json"], ["scan"], ["--apply-plan", "a.json", "b.json"],
])
def test_helper_accepts_only_apply_plan(argv, as_admin, monkeypatch, capsys):
    monkeypatch.setattr(engine, "execute_plan", lambda *a, **k: pytest.fail("must not execute"))
    assert helper_main.main(argv) == common.EXIT_USAGE
    assert "usage: driver-installer-helper --apply-plan" in capsys.readouterr().err


def test_helper_survives_missing_stdout(as_user, monkeypatch):
    monkeypatch.setattr(sys, "stderr", None)               # windowless helper.exe
    monkeypatch.setattr(sys, "stdout", None)
    assert helper_main.main(["--apply-plan", "x"]) == common.EXIT_ELEVATION
