"""Integration: scan -> verify -> dry run / elevate -> helper re-verifies -> restore point -> install.

The Windows flow runs against the WMI fixtures and a fake command runner; the
download is a real HTTP transfer from a loopback server; signatures are real
Ed25519. Nothing here needs, or uses, real administrator rights.
"""
import hashlib
import json
import sys
from pathlib import Path

import pytest

import cli
import demo
import helper_main
from conftest import (FIXTURES, RESTORE_CREATED, RESTORE_DISABLED, authenticode_json, driver_zip,
                      windows_powershell)
from core import common, elevation, engine, manifest, scanner_win, trust
from core.common import ElevationError


def wifi_package(base: str, payload: bytes, **install) -> dict:
    return {"id": "intel.wifi.ax210", "name": "Intel Wi-Fi 6E AX210 driver", "vendor": "Intel", "category": "driver",
            "version": "23.60.1.2", "class_guid": "{4d36e972-e325-11ce-bfc1-08002be10318}",
            "platform": {"os": "windows", "arch": ["x86_64"]}, "hardware_ids": ["pci:8086:2725"],
            "artifact": {"url": f"{base}/wifi.zip", "filename": "wifi.zip", "size": len(payload),
                         "sha256": hashlib.sha256(payload).hexdigest(), "format": "zip",
                         "signature": {"type": "authenticode", "subject": "O=Intel Corporation", "target": "catalog"}},
            "install": {"method": "pnputil", "inf_path": "x200.inf", "reboot_required": False, **install},
            "upstream": {"source": "vendor", "reference_url": "https://example.invalid/wifi"}}


@pytest.fixture
def win_env(tmp_path, monkeypatch, runner, windows, loopback, pin):
    """A simulated Windows PC with one outdated Wi-Fi driver and a signed manifest offering the update."""
    www = tmp_path / "www"
    www.mkdir()
    payload = driver_zip()
    (www / "wifi.zip").write_bytes(payload)
    server, base = demo.serve(www)
    monkeypatch.setattr(scanner_win, "default_source", lambda: scanner_win.FixtureWmiSource(FIXTURES / "wmi"))
    runner.on("powershell", windows_powershell())

    class Env:
        pass
    env = Env()
    env.runner, env.tmp, env.base, env.payload = runner, tmp_path, base, payload
    env.elevations = []

    def publish(**install):
        raw, sig = pin(demo.manifest_shell([wifi_package(base, payload, **install)]))
        (tmp_path / "manifest.json").write_bytes(raw)
        (tmp_path / "manifest.json.sig").write_bytes(sig)
        return ["--manifest", str(tmp_path / "manifest.json")]
    env.publish = publish

    def verified_updates(**install):
        """Run the unprivileged half: load manifest, scan, download + verify."""
        env.publish(**install)
        ctx = engine.Context()
        engine.load_manifest_files(ctx, tmp_path / "manifest.json", tmp_path / "manifest.json.sig")
        devices, upgrades = engine.scan()
        updates = manifest.find_updates(devices, ctx.manifest, upgrades)
        for u in updates:
            engine.verify_update(u, ctx)
        return ctx, updates
    env.verified_updates = verified_updates

    def helper_runs_elevated(argv, timeout=None):
        """Stand-in for UAC: record the request, then run the helper entry point 'as administrator'."""
        env.elevations.append(argv)
        monkeypatch.setattr(elevation, "is_admin", lambda: True)
        try:
            return helper_main.main(argv[3:])
        finally:
            monkeypatch.setattr(elevation, "is_admin", lambda: False)
    env.helper_runs_elevated = helper_runs_elevated
    yield env
    server.shutdown()


def installed(env) -> list[list[str]]:
    return env.runner.ran("pnputil")


def restore_points(env) -> int:
    return sum(1 for _, _, e in env.runner.calls if "SD_DESC" in e)


# ------------------------------------------------------------------ dry run
def test_dry_run_is_the_default_and_never_elevates_or_installs(win_env, as_user, monkeypatch, capsys):
    monkeypatch.setattr(elevation, "run_elevated", lambda *a, **k: pytest.fail("dry run must not elevate"))
    code = cli.main(["--update-all", *win_env.publish()])
    out = capsys.readouterr().out
    assert code == 0
    assert "22.250.1.2 -> 23.60.1.2" in out and "verified: SHA-256 OK" in out
    assert "DRY RUN - nothing was installed" in out
    assert "Checkpoint-Computer" in out and "pnputil /add-driver <extract-dir>\\x200.inf /install" in out
    assert installed(win_env) == [] and restore_points(win_env) == 0
    assert not (win_env.tmp / "system").exists()          # the privileged state directory was never touched


def test_explicit_dry_run_flag_and_json_output(win_env, as_user, monkeypatch, capsys):
    monkeypatch.setattr(elevation, "run_elevated", lambda *a, **k: pytest.fail("dry run must not elevate"))
    assert cli.main(["--update-all", "--dry-run", "--json", *win_env.publish()]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["mode"] == "dry-run" and report["updates"][0]["package"] == "intel.wifi.ax210"
    assert installed(win_env) == []
    with pytest.raises(SystemExit):                        # --dry-run and --apply are mutually exclusive
        cli.main(["--update-all", "--dry-run", "--apply"])


def test_apply_without_confirmation_does_nothing(win_env, as_user, monkeypatch, capsys):
    monkeypatch.setattr(elevation, "run_elevated", lambda *a, **k: pytest.fail("must not elevate unconfirmed"))
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False, raising=False)     # e.g. a cron job or a pipe
    assert cli.main(["--update-all", "--apply", *win_env.publish()]) == cli.EXIT_NOT_CONFIRMED
    assert "Not confirmed; nothing was installed" in capsys.readouterr().out
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr("builtins.input", lambda prompt: "yes")                # must type 'install'
    assert cli.main(["--update-all", "--apply", *win_env.publish()]) == cli.EXIT_NOT_CONFIRMED
    assert installed(win_env) == []


# ---------------------------------------------------------------- elevation
def test_apply_as_ordinary_user_requests_elevation_for_the_helper_only(win_env, as_user, monkeypatch, capsys):
    monkeypatch.setattr(elevation, "run_elevated", win_env.helper_runs_elevated)
    code = cli.main(["--update-all", "--apply", "--yes", *win_env.publish()])
    out = capsys.readouterr().out
    assert code == 0 and "Intel Wi-Fi 6E AX210 driver: installed" in out and "Restore point: created" in out
    (argv,) = win_env.elevations                             # exactly one elevation request
    assert argv[:2] == [sys.executable, "-I"] and argv[2].endswith("helper_main.py") and argv[3] == "--apply-plan"
    plan = json.loads(Path(argv[4]).read_text())
    assert plan["items"][0]["package_id"] == "intel.wifi.ax210" and plan["allow_without_snapshot"] is False
    # catalog signature checked once before elevation, then inside the helper: lock staging dir,
    # catalog signature again, restore point, then pnputil
    kinds = [p if p != "powershell" else ("authenticode" if "SD_FILE" in e else "restore")
             for p, _, e in win_env.runner.calls if p != "powershell" or "SD_FILE" in e or "SD_DESC" in e]
    assert kinds == ["authenticode", "icacls", "authenticode", "restore", "pnputil"]
    assert json.loads((win_env.tmp / "system" / "results" / f"{plan['plan_id']}.json").read_text())["status"] == "ok"


def test_declined_uac_prompt_installs_nothing(win_env, as_user, monkeypatch, capsys):
    def declined(argv, timeout=None):
        raise ElevationError("the UAC prompt was declined")
    monkeypatch.setattr(elevation, "run_elevated", declined)
    assert cli.main(["--update-all", "--apply", "--yes", *win_env.publish()]) == cli.EXIT_ELEVATION
    assert "Nothing was installed" in capsys.readouterr().err and installed(win_env) == []


def test_helper_entry_point_refuses_to_run_unelevated(win_env, as_user, capsys):
    ctx, updates = win_env.verified_updates()
    plan_path, _ = engine.write_plan(updates, ctx)
    assert helper_main.main(["--apply-plan", str(plan_path)]) == cli.EXIT_ELEVATION
    with pytest.raises(ElevationError):
        engine.execute_plan(plan_path)
    assert installed(win_env) == []


def test_already_elevated_process_installs_without_a_second_prompt(win_env, as_admin, monkeypatch):
    monkeypatch.setattr(elevation, "run_elevated", lambda *a, **k: pytest.fail("already elevated"))
    ctx, updates = win_env.verified_updates()
    result = engine.apply(updates, ctx)
    assert result["status"] == "ok" and len(installed(win_env)) == 1


def test_demo_mode_can_never_install(win_env, as_admin):
    ctx, updates = win_env.verified_updates()
    ctx.demo = True
    with pytest.raises(common.InstallError, match="never installs"):
        engine.apply(updates, ctx)


# ------------------------------------------- the helper distrusts its caller
def test_helper_rejects_a_file_swapped_after_user_side_verification(win_env, as_admin):
    ctx, updates = win_env.verified_updates()
    assert updates[0].status == "verified"
    quarantined = Path(updates[0].path)
    quarantined.chmod(0o600)
    data = bytearray(quarantined.read_bytes())
    data[-1] ^= 0xFF                                         # same size, one byte different
    quarantined.write_bytes(bytes(data))
    result = engine.apply(updates, ctx)
    assert result["status"] == "refused" and "SHA-256 MISMATCH" in result["items"][0]["detail"]
    assert installed(win_env) == [] and restore_points(win_env) == 0


def test_helper_rejects_a_manifest_not_signed_by_a_pinned_key(win_env, as_admin, monkeypatch):
    ctx, updates = win_env.verified_updates()
    plan_path, _ = engine.write_plan(updates, ctx)
    evil_raw, evil_sig, _ = demo.sign(demo.manifest_shell([wifi_package(win_env.base, win_env.payload)]))
    plan = json.loads(plan_path.read_text())
    Path(plan["manifest"]).write_bytes(evil_raw)             # attacker supplies their own correctly signed manifest
    Path(plan["signature"]).write_bytes(evil_sig)
    result = engine.execute_plan(plan_path)
    assert result["status"] == "refused" and "pinned key" in result["detail"] and installed(win_env) == []


def test_helper_rejects_packages_missing_from_the_manifest_and_bad_plans(win_env, as_admin):
    ctx, updates = win_env.verified_updates()
    plan_path, _ = engine.write_plan(updates, ctx)
    plan = json.loads(plan_path.read_text())
    plan["items"] = [{"package_id": "evil.package", "file": updates[0].path}]
    plan_path.write_text(json.dumps(plan))
    result = engine.execute_plan(plan_path)
    assert result["status"] == "refused" and "not in the signed manifest" in result["items"][0]["detail"]
    for bad in ({"plan_id": "../../etc/x", "items": plan["items"]}, {"plan_id": plan["plan_id"], "items": []},
                {"plan_id": plan["plan_id"], "items": [{"fwupd_device": "--force"}]}, ["not", "a", "dict"]):
        plan_path.write_text(json.dumps(bad))
        assert engine.execute_plan(plan_path)["status"] == "refused"
    assert installed(win_env) == []
    assert sorted(p.name for p in (win_env.tmp / "system" / "results").iterdir()) == [f"{plan['plan_id']}.json"]


def test_catalog_from_another_publisher_stops_the_install(win_env, as_admin):
    win_env.runner.on("powershell", windows_powershell(signer=authenticode_json(subject="CN=Evil, O=Evil Corp")))
    ctx, updates = win_env.verified_updates()
    assert updates[0].status == "failed" and updates[0].check("publisher").state == "failed"   # caught before elevation
    assert "not the pinned publisher" in updates[0].check("publisher").reason and updates[0].path == ""
    # and if the catalog is swapped after the user-side check, the helper still refuses it
    win_env.runner.on("powershell", windows_powershell())
    ctx, updates = win_env.verified_updates()
    assert updates[0].status == "verified"
    win_env.runner.on("powershell", windows_powershell(signer=authenticode_json(subject="CN=Evil, O=Evil Corp")))
    result = engine.apply(updates, ctx)
    assert result["status"] == "refused" and "not the pinned publisher" in result["items"][0]["detail"]
    assert installed(win_env) == [] and restore_points(win_env) == 0     # refused before any restore point


# ------------------------------------------------------------ restore point
def test_no_restore_point_means_no_install_until_the_user_agrees(win_env, as_admin):
    win_env.runner.on("powershell", windows_powershell(restore=RESTORE_DISABLED))
    ctx, updates = win_env.verified_updates()
    result = engine.apply(updates, ctx)
    assert result["status"] == "snapshot_failed" and result["snapshot_required"] is False
    assert "System Restore is disabled" in result["detail"] and installed(win_env) == []
    result = engine.apply(updates, ctx, allow_without_snapshot=True)       # the user said: continue anyway
    assert result["status"] == "ok" and len(installed(win_env)) == 1
    assert result["snapshot"]["status"] == "failed"                         # and the record says so


def test_cli_prompts_before_continuing_without_a_restore_point(win_env, as_user, monkeypatch, capsys):
    win_env.runner.on("powershell", windows_powershell(restore=RESTORE_DISABLED))
    monkeypatch.setattr(elevation, "run_elevated", win_env.helper_runs_elevated)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True, raising=False)
    answers = iter(["install", "n"])
    monkeypatch.setattr("builtins.input", lambda prompt: next(answers))
    assert cli.main(["--update-all", "--apply", *win_env.publish()]) == cli.EXIT_SNAPSHOT
    assert installed(win_env) == [] and len(win_env.elevations) == 1
    answers = iter(["install", "y"])
    assert cli.main(["--update-all", "--apply", *win_env.publish()]) == 0
    assert len(installed(win_env)) == 1 and len(win_env.elevations) == 3     # second prompt, second elevation


def test_package_that_requires_a_snapshot_cannot_be_overridden(win_env, as_admin):
    win_env.runner.on("powershell", windows_powershell(restore=RESTORE_DISABLED))
    ctx, updates = win_env.verified_updates(snapshot_required=True)
    result = engine.apply(updates, ctx, allow_without_snapshot=True)
    assert result["status"] == "snapshot_failed" and result["snapshot_required"] is True
    assert installed(win_env) == []


def test_reboot_required_is_reported(win_env, as_admin):
    win_env.runner.on("pnputil", common.Result(3010, "Driver package added. System reboot is needed.", ""))
    ctx, updates = win_env.verified_updates()
    result = engine.apply(updates, ctx)
    assert result["status"] == "ok" and result["reboot_required"] is True


# -------------------------------------------------------------------- Linux
@pytest.fixture
def linux_env(runner, linux, pin, as_admin):
    pkg = {"id": "distro.nvidia.driver", "name": "NVIDIA driver (distro package)", "vendor": "NVIDIA",
           "category": "driver", "version": "550.120",
           "platform": {"os": "linux", "arch": ["x86_64"], "distros": ["ubuntu"]}, "hardware_ids": ["pci:10de:2684"],
           "install": {"method": "package-manager", "package_name": "nvidia-driver-550", "reboot_required": True},
           "upstream": {"source": "distro", "reference_url": "https://example.invalid/nvidia"}}
    raw, sig = pin(demo.manifest_shell([pkg]))
    from core.model import Device
    gpu = Device("GeForce RTX 4090 (VGA compatible controller)", kind="pci", hardware_ids=["pci:10de:2684"],
                 driver="nouveau", driver_version="in-kernel 6.8.0")
    fw = Device("NVMe SSD", kind="fwupd", hardware_ids=["fwupd:x"], driver_version="1.0", address="c" * 40)
    ctx = engine.Context(manifest=manifest.load_manifest(raw, sig), manifest_raw=raw, signature=sig)
    updates = manifest.find_updates([gpu, fw], ctx.manifest, {"c" * 40: {"Version": "1.1", "Name": "NVMe firmware"}})
    return runner, ctx, updates


def test_linux_snapshot_precedes_package_manager_and_fwupd(linux_env):
    runner, ctx, updates = linux_env
    runner.available = {"timeshift", "apt-get", "fwupdmgr"}
    assert [u.status for u in updates] == ["delegated", "delegated"]
    plan = engine.dry_run_plan(updates)
    assert plan[0].startswith("[elevated] timeshift --create") and runner.calls == []
    result = engine.apply(updates, ctx)
    assert result["status"] == "ok" and result["reboot_required"] is True
    assert runner.programs() == ["timeshift", "fwupdmgr", "apt-get"]
    assert runner.ran("fwupdmgr")[0][:2] == ["update", "c" * 40]


def test_linux_without_snapshot_tool_warns_and_continues(linux_env, tmp_path):
    runner, ctx, updates = linux_env
    runner.available = {"apt-get", "fwupdmgr"}
    result = engine.apply(updates, ctx)
    assert result["status"] == "ok" and result["snapshot"]["status"] == "unavailable"
    events = [json.loads(line)["event"] for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
    assert events.index("restore.warning") < events.index("install.start")


def test_linux_failing_snapshot_tool_blocks_the_install(linux_env):
    runner, ctx, updates = linux_env
    runner.available = {"snapper", "apt-get", "fwupdmgr"}
    runner.on("snapper", common.Result(1, "", "No such config: root"))
    result = engine.apply(updates, ctx)
    assert result["status"] == "snapshot_failed" and runner.ran("apt-get") == [] and runner.ran("fwupdmgr") == []


def test_audit_log_records_the_whole_run_and_stays_intact(win_env, as_admin, tmp_path):
    ctx, updates = win_env.verified_updates()
    engine.apply(updates, ctx)
    ok, msg = common.AuditLog.verify_chain(tmp_path / "audit.jsonl")
    assert ok, msg
    events = [json.loads(line)["event"] for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
    for needed in ("manifest.accepted", "scan.windows.done", "net.request", "verify.sha256_ok", "apply.requested",
                   "helper.start", "signature.authenticode", "restore.created", "install.start", "install.result"):
        assert needed in events, needed
