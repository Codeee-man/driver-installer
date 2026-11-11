"""Itemised check records written by engine.verify_update, per kind of update, and the
Full / Partial / None level the UI derives from them (ui/verification.py, no Qt)."""
import json

import pytest

import cli
import demo
from conftest import KNOWN_BAD_SYS, authenticode_json, driver_zip, windows_powershell
from core import engine
from core.discovery import linux_lvfs
from core.model import CHECK_ORDER, Device, Update
from test_apply_flow import win_env, wifi_package  # noqa: F401
from ui import verification as vf


def states(update) -> dict:
    return {c.key: c.state for c in update.checks}


def test_set_check_keeps_order_and_replaces():
    u = Update(Device("d"), "n", "1", "2", "s")
    u.set_check("publisher", "passed", "a")
    u.set_check("sha256", "skipped", "b")
    u.set_check("sha256", "passed", "c")
    assert [(c.key, c.state, c.reason) for c in u.checks] == [("sha256", "passed", "c"), ("publisher", "passed", "a")]
    assert u.check("sha256").label == "SHA-256 integrity" and u.check("manifest") is None


@pytest.mark.parametrize("checks,status,expected", [
    ({"sha256": "passed", "manifest": "passed", "blocklist": "passed", "publisher": "passed"}, "verified", "Full"),
    ({"sha256": "passed", "manifest": "not_applicable", "blocklist": "passed", "publisher": "passed"}, "verified", "Full"),
    ({k: "not_applicable" for k in CHECK_ORDER}, "delegated", "Full"),
    ({"sha256": "passed", "manifest": "passed", "blocklist": "skipped", "publisher": "passed"}, "verified", "Partial"),
    ({"sha256": "failed", "manifest": "passed", "blocklist": "skipped", "publisher": "skipped"}, "failed", "None"),
    ({"sha256": "passed", "manifest": "passed", "blocklist": "failed", "publisher": "passed"}, "verified", "None"),
    ({}, "pending", "Pending"),
    ({}, "failed", "None"),
])
def test_level_rules(checks, status, expected):
    u = Update(Device("d"), "n", "1", "2", "s", status=status)
    for key, state in checks.items():
        u.set_check(key, state, "r")
    assert vf.level(u) == expected
    assert vf.level(None) == ""


def test_manifest_driver_on_windows_is_full(win_env, as_user):
    ctx, (update,) = win_env.verified_updates()
    assert states(update) == {"sha256": "passed", "manifest": "passed", "blocklist": "passed", "publisher": "passed"}
    assert "pinned key" in update.check("manifest").reason
    assert update.check("blocklist").reason.startswith("1 .sys file(s) compared with")
    assert "x200.cat signed by O=Intel Corporation" in update.check("publisher").reason
    assert vf.level(update) == "Full"


def test_blocklist_offline_gives_partial_with_the_reason(win_env, as_user, monkeypatch):
    from core.security import loldrivers

    def down(*a, **k):
        raise loldrivers.BlocklistUnavailable("connection timed out")
    monkeypatch.setattr(loldrivers, "fetch", down)
    ctx, (update,) = win_env.verified_updates()
    assert update.status == "verified" and vf.level(update) == "Partial"
    assert update.check("blocklist").state == "skipped"
    assert update.check("blocklist").reason == ("LOLDrivers database offline (connection timed out); "
                                                "checked again before installing")
    assert vf.missing_summary(update).startswith("LOLDrivers BYOVD check skipped (LOLDrivers database offline")


def test_wrong_hash_is_none_and_later_checks_are_marked_not_reached(win_env, as_user):
    pkg = wifi_package(win_env.base, win_env.payload)
    pkg["artifact"]["sha256"] = "0" * 64
    ctx = engine.Context(manifest={"packages": [pkg]})
    devices, upgrades = engine.scan()
    (update,) = engine.find_all_updates(devices, upgrades, ctx)
    engine.verify_update(update, ctx)
    assert states(update) == {"sha256": "failed", "manifest": "passed", "blocklist": "skipped", "publisher": "skipped"}
    assert "SHA-256 MISMATCH" in update.check("sha256").reason
    assert update.check("publisher").reason == "not reached: an earlier step failed"
    assert vf.level(update) == "None"


def test_blocklisted_sys_is_a_failed_blocklist_check(win_env, as_user):
    payload = driver_zip({"evil.sys": KNOWN_BAD_SYS})
    (win_env.tmp / "www" / "wifi.zip").write_bytes(payload)
    ctx = engine.Context(manifest={"packages": [wifi_package(win_env.base, payload)]})
    devices, upgrades = engine.scan()
    (update,) = engine.find_all_updates(devices, upgrades, ctx)
    engine.verify_update(update, ctx)
    assert update.check("sha256").state == "passed"
    assert update.check("blocklist").state == "failed" and "SECURITY ALERT: evil.sys" in update.check("blocklist").reason
    assert vf.level(update) == "None"


def test_unpinned_publisher_is_a_failed_publisher_check(win_env, as_user):
    win_env.runner.on("powershell", windows_powershell(signer=authenticode_json(subject="CN=x, O=Evil Corp")))
    ctx, (update,) = win_env.verified_updates()
    assert update.check("publisher").state == "failed" and vf.level(update) == "None"


def test_fwupd_and_distro_updates_are_full_with_reasons(runner, linux):
    fw = Update(Device("SSD", kind="fwupd", address="c" * 40), "SSD firmware", "1", "2", "fwupd / LVFS",
                status="delegated")
    engine.verify_update(fw, engine.Context())
    assert set(states(fw).values()) == {"not_applicable"} and vf.level(fw) == "Full"
    assert "LVFS" in fw.check("manifest").reason
    rec = linux_lvfs.Recommendation("nvidia-driver-550", "apt-get", "ubuntu-drivers", "pci:10de:2684", "recommended")
    repo = Update(Device("GPU"), "nvidia", "-", "550", "distro", package=linux_lvfs.to_package(rec), status="delegated")
    engine.verify_update(repo, engine.Context())
    assert vf.level(repo) == "Full" and "distribution" in repo.check("manifest").reason


def test_demo_packages_are_never_full(tmp_path, linux):
    devices = [Device("A", hardware_ids=["pci:1:1"]), Device("B", hardware_ids=["pci:2:2"])]
    ctx = demo.build(devices, tmp_path)
    good, bad = engine.find_all_updates(devices, {}, ctx)
    for u in (good, bad):
        engine.verify_update(u, ctx)
    assert vf.level(good) == "Partial" and "throwaway key" in good.check("manifest").reason
    assert vf.level(bad) == "None" and good.check("blocklist").state in ("skipped", "not_applicable")


def test_cli_json_carries_level_and_checks(win_env, as_user, capsys):
    assert cli.main(["update", "--all", "--json", *win_env.publish()]) == 0
    (record,) = json.loads(capsys.readouterr().out)["updates"]
    assert record["verification"] == "Full"
    assert [c["check"] for c in record["checks"]] == list(CHECK_ORDER)
