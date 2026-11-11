"""Live BYOVD protection: LOLDrivers feed (mock HTTP), .sys hashing, pipeline abort and purge."""
import hashlib
import io
import json
import zipfile
from pathlib import Path

import pytest

import cli
from conftest import KNOWN_BAD_SYS, REAL_LOLDRIVERS_FETCH, driver_zip, loldrivers_feed, canned_blocklist, windows_powershell
from core import common, elevation, engine, installer
from core.common import VerificationError
from core.security import loldrivers
from mock_http import MockFeed
from test_apply_flow import installed, restore_points, win_env, wifi_package  # noqa: F401
import demo

BAD_SHA = hashlib.sha256(KNOWN_BAD_SYS).hexdigest()


# ------------------------------------------------------------------- feed
def test_feed_is_fetched_over_http_into_memory_only(tmp_path):
    feed = MockFeed(loldrivers_feed())
    try:
        blocklist = REAL_LOLDRIVERS_FETCH(feed.url, allow_loopback_http=True)
    finally:
        feed.close()
    assert feed.hits == 1 and blocklist.drivers == 602 and len(blocklist) == 600 * 3 + 1
    assert isinstance(blocklist.by_hash["SHA256"], dict)                    # O(1) lookups
    hit = blocklist.lookup(BAD_SHA)
    assert (hit.driver_id, hit.category, hit.name) == ("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "malicious", "evil.sys")
    assert blocklist.lookup(BAD_SHA.upper()) == hit and blocklist.lookup("0" * 64) is None
    written = [p for p in tmp_path.rglob("*") if p.is_file() and p.name != "audit.jsonl"]
    assert written == []                                                    # nothing cached on disk


def test_entries_without_sha256_are_tolerated_and_sha1_md5_still_match():
    extra = [{"Filename": "old.sys", "SHA1": hashlib.sha1(b"old").hexdigest(), "MD5": hashlib.md5(b"old").hexdigest()},
             {"Filename": "junk.sys", "SHA256": "not-a-hash", "SHA1": "", "MD5": None}]
    blocklist = loldrivers.parse(loldrivers_feed(extra))
    assert blocklist.lookup("f" * 64, sha1=hashlib.sha1(b"old").hexdigest()).name == "old.sys"
    assert blocklist.lookup("f" * 64, md5=hashlib.md5(b"old").hexdigest()).name == "old.sys"
    assert "not-a-hash" not in blocklist.by_hash["SHA256"]


@pytest.mark.parametrize("body,status,why", [
    (loldrivers_feed(), 503, "could not fetch"),
    (b"<html>maintenance</html>", 200, "not valid JSON"),
    (loldrivers_feed(filler=3), 200, "truncated or tampered"),              # an attacker serving a near-empty list
    (b"[]", 200, "truncated or tampered"),
    (json.dumps({"error": "nope"}).encode(), 200, "truncated or tampered"),
    (b'"just a string"', 200, "unexpected shape"),
])
def test_bad_feed_is_unavailable_never_an_empty_blocklist(body, status, why):
    feed = MockFeed(body, status)
    try:
        with pytest.raises(loldrivers.BlocklistUnavailable, match=why):
            REAL_LOLDRIVERS_FETCH(feed.url, allow_loopback_http=True)
    finally:
        feed.close()


def test_feed_is_never_fetched_over_plain_http():
    with pytest.raises(loldrivers.BlocklistUnavailable, match="non-HTTPS"):
        REAL_LOLDRIVERS_FETCH("http://www.loldrivers.io/api/drivers.json")
    assert loldrivers.URL.startswith("https://www.loldrivers.io/")


# ------------------------------------------------------------- .sys files
def test_directory_check_hashes_every_sys_file(tmp_path):
    (tmp_path / "sub").mkdir()
    (tmp_path / "good.sys").write_bytes(b"MZ good")
    (tmp_path / "readme.txt").write_bytes(KNOWN_BAD_SYS)                    # not a .sys: not a driver image
    checked = loldrivers.check_directory(tmp_path, canned_blocklist())
    assert [c["file"] for c in checked] == ["good.sys"]
    (tmp_path / "sub" / "RENAMED.SYS").write_bytes(KNOWN_BAD_SYS)           # matched by content, any name or case
    with pytest.raises(loldrivers.SecurityAlert) as exc:
        loldrivers.check_directory(tmp_path, canned_blocklist())
    (match,) = exc.value.matches
    assert match["file"] == "sub/RENAMED.SYS" and match["sha256"] == BAD_SHA and match["category"] == "malicious"
    assert "SECURITY ALERT" in str(exc.value) and isinstance(exc.value, VerificationError)
    events = [json.loads(line)["event"] for line in Path(common.audit_log().path).read_text().splitlines()]
    assert "security.alert" in events


def test_zip_members_are_hashed_without_extracting(tmp_path):
    clean, bad = tmp_path / "clean.zip", tmp_path / "bad.zip"
    clean.write_bytes(driver_zip())
    bad.write_bytes(driver_zip({"drivers/x64/helper.sys": KNOWN_BAD_SYS}))
    assert [c["file"] for c in loldrivers.check_archive(clean, "zip", canned_blocklist())] == ["x200.sys"]
    with pytest.raises(loldrivers.SecurityAlert, match="helper.sys"):
        loldrivers.check_archive(bad, "zip", canned_blocklist())
    assert sorted(p.name for p in tmp_path.iterdir() if p.name != "audit.jsonl") == ["bad.zip", "clean.zip"]
    (tmp_path / "broken.zip").write_bytes(b"not a zip")
    with pytest.raises(VerificationError, match="not a readable zip"):
        loldrivers.check_archive(tmp_path / "broken.zip", "zip", canned_blocklist())


def test_cab_is_unpacked_to_a_temp_dir_that_is_always_purged(tmp_path, runner, windows, monkeypatch):
    seen = []

    def expand(cmd, env):
        target = Path(cmd[3])
        seen.append(target)
        (target / "evil.sys").write_bytes(KNOWN_BAD_SYS)
        return common.Result(0)
    runner.on("expand", expand)
    with pytest.raises(loldrivers.SecurityAlert):
        loldrivers.check_archive(tmp_path / "x.cab", "cab", canned_blocklist())
    assert seen and not seen[0].exists()                                   # purged despite the alert
    monkeypatch.setattr(common, "OS_NAME", "linux")
    assert loldrivers.check_archive(tmp_path / "x.cab", "cab", canned_blocklist()) is None    # deferred to the helper


# -------------------------------------------------------------- installer
def test_installer_blocks_a_listed_driver_before_pnputil(runner, as_admin, windows, tmp_path):
    from test_installer import win_pkg
    runner.on("powershell", windows_powershell())
    staged = tmp_path / "pkg.zip"
    staged.write_bytes(driver_zip({"byovd.sys": KNOWN_BAD_SYS}))
    with pytest.raises(loldrivers.SecurityAlert):
        installer.install(win_pkg(), staged, dry_run=False, workdir=tmp_path, blocklist=canned_blocklist())
    assert runner.calls == []                               # not even the signature check ran; certainly not pnputil
    clean = tmp_path / "clean.zip"
    clean.write_bytes(driver_zip())
    (tmp_path / "w2").mkdir()
    assert installer.install(win_pkg(), clean, dry_run=False, workdir=tmp_path / "w2",
                             blocklist=canned_blocklist()).status == "installed"


# ---------------------------------------------------------------- pipeline
def publish(env, pin, packages):
    raw, sig = pin(demo.manifest_shell(packages))
    (env.tmp / "manifest.json").write_bytes(raw)
    (env.tmp / "manifest.json.sig").write_bytes(sig)
    ctx = engine.Context()
    engine.load_manifest_files(ctx, env.tmp / "manifest.json", env.tmp / "manifest.json.sig")
    return ctx


def serve_bad_package(env) -> dict:
    payload = driver_zip({"vuln.sys": KNOWN_BAD_SYS})
    (env.tmp / "www" / "bad.zip").write_bytes(payload)
    pkg = wifi_package(env.base, payload)
    pkg.update(id="realtek.usb.nic", name="Realtek USB NIC driver", hardware_ids=["usb:0bda:8153"], version="11.0.0.0")
    pkg["artifact"].update(url=f"{env.base}/bad.zip", filename="bad.zip")
    return pkg


def test_user_side_check_purges_a_listed_driver_right_after_download(win_env, as_user, pin, monkeypatch):
    monkeypatch.setattr(elevation, "run_elevated", lambda *a, **k: pytest.fail("must never reach elevation"))
    ctx = publish(win_env, pin, [serve_bad_package(win_env)])
    devices, upgrades = engine.scan()
    (update,) = engine.find_all_updates(devices, upgrades, ctx)
    engine.verify_update(update, ctx)
    assert update.status == "failed" and "SECURITY ALERT: vuln.sys" in update.detail and "file purged" in update.detail
    assert list(ctx.quarantine.iterdir()) == [] and engine.ready([update]) == []


def test_helper_fetches_live_and_aborts_the_whole_plan_on_a_hit(win_env, as_admin, pin, monkeypatch, tmp_path):
    """Even if the user-side check was bypassed, the helper's own fetch + check stops everything."""
    ctx = publish(win_env, pin, [wifi_package(win_env.base, win_env.payload), serve_bad_package(win_env)])
    devices, upgrades = engine.scan()
    updates = engine.find_all_updates(devices, upgrades, ctx)
    feed = {"lists_the_bad_driver": False}

    def fetch(*a, **k):
        return canned_blocklist() if feed["lists_the_bad_driver"] else loldrivers.parse(loldrivers_feed(filler=5)
                                                                                    .replace(BAD_SHA.upper().encode(), b"1" * 64), minimum=1)
    monkeypatch.setattr(loldrivers, "fetch", fetch)
    for u in updates:
        engine.verify_update(u, ctx)                       # user side sees a feed without the bad hash
    assert [u.status for u in updates] == ["verified", "verified"]
    stage = tmp_path / "stage"
    monkeypatch.setattr(engine, "_staging_dir", lambda: (stage.mkdir(), stage)[1])
    feed["lists_the_bad_driver"] = True                    # by install time the feed lists it
    result = engine.apply(updates, ctx)
    assert result["status"] == "security_alert" and result["alerts"] == ["realtek.usb.nic"]
    assert result["matches"][0]["sha256"] == BAD_SHA and "known malicious" in result["detail"]
    assert installed(win_env) == [] and restore_points(win_env) == 0        # the clean package was not installed either
    assert not stage.exists()                                               # staged copies and unpacked files purged
    bad = next(u for u in updates if engine.update_key(u) == "realtek.usb.nic")
    assert bad.status == "failed" and bad.path == ""
    assert [p.name for p in ctx.quarantine.iterdir()] == [Path(updates[0].path).name]   # only the clean file remains
    assert common.RESULT_EXIT["security_alert"] == 6


def test_unreachable_blocklist_stops_the_install_until_the_user_agrees(win_env, as_admin, monkeypatch):
    ctx, updates = win_env.verified_updates()

    def down(*a, **k):
        raise loldrivers.BlocklistUnavailable("connection timed out")
    monkeypatch.setattr(loldrivers, "fetch", down)
    result = engine.apply(updates, ctx)
    assert result["status"] == "blocklist_unavailable" and "Nothing was installed" in result["detail"]
    assert installed(win_env) == [] and restore_points(win_env) == 0
    result = engine.apply(updates, ctx, allow_without_blocklist=True)
    assert result["status"] == "ok" and result["blocklist"] == "skipped at the user's request"
    assert len(installed(win_env)) == 1


def test_cli_prompts_and_flags_for_missing_blocklist_and_reports_alerts(win_env, as_user, monkeypatch, capsys, pin):
    import sys

    def down(*a, **k):
        raise loldrivers.BlocklistUnavailable("offline")
    monkeypatch.setattr(loldrivers, "fetch", down)
    monkeypatch.setattr(elevation, "run_elevated", win_env.helper_runs_elevated)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True, raising=False)
    answers = iter(["install", "n"])
    monkeypatch.setattr("builtins.input", lambda prompt: next(answers))
    assert cli.main(["update", "--all", "--apply", *win_env.publish()]) == common.EXIT_BLOCKLIST
    assert installed(win_env) == []
    assert cli.main(["update", "--all", "--apply", "-y", "--skip-blocklist", *win_env.publish()]) == 0
    assert len(installed(win_env)) == 1
    capsys.readouterr()
    monkeypatch.setattr(loldrivers, "fetch", lambda *a, **k: canned_blocklist())
    raw, sig = pin(demo.manifest_shell([serve_bad_package(win_env)]))
    (win_env.tmp / "manifest.json").write_bytes(raw)
    (win_env.tmp / "manifest.json.sig").write_bytes(sig)
    monkeypatch.setattr(engine, "_precheck_blocklist", lambda *a: "")       # pretend the user-side check was skipped
    code = cli.main(["update", "--all", "--apply", "-y", "--manifest", str(win_env.tmp / "manifest.json")])
    err = capsys.readouterr().err
    assert code == common.EXIT_SECURITY and "SECURITY ALERT: vuln.sys" in err and "Nothing was installed" in err
    assert len(installed(win_env)) == 1                    # still only the earlier, clean install


def test_plans_without_windows_driver_packages_do_not_fetch_the_feed(runner, linux, as_admin, pin, monkeypatch):
    monkeypatch.setattr(loldrivers, "fetch", lambda *a, **k: pytest.fail("no .sys involved: no fetch"))
    runner.available = {"fwupdmgr"}
    from core.model import Device, Update
    fw = Device("NVMe SSD", kind="fwupd", driver_version="1.0", address="c" * 40)
    update = Update(fw, "NVMe firmware", "1.0", "1.1", "fwupd / LVFS", "", None, "delegated")
    assert engine.apply([update], engine.Context())["status"] == "ok"
