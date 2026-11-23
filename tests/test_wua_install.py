"""Fixes from live Windows testing of v1.1.4: cabinets keep their folders and all parts of an
update share one tree, localized tool output is decoded with the console (OEM) code page, the
window follows the elevated installer live through its log, and pnputil "file not found" on a
Windows Update item falls back to the Windows Update Agent's installer."""
import json
import threading
import time
from pathlib import Path

import pytest

from conftest import windows_powershell, wua_fetch_result
from core import common, engine, installer
from core.discovery import windows_update
from core.common import InstallError

UID = "a1b2c3d4-0000-4000-8000-0000000000aa"


# ------------------------------------------------------------ cabinets
def fake_tar(layout: dict):
    """tar -xf <cab> -C <dest>: writes `layout` (relative path -> bytes), folders included."""
    def run(cmd, env):
        dest = Path(cmd[cmd.index("-C") + 1])
        for rel, data in layout.items():
            (dest / rel).parent.mkdir(parents=True, exist_ok=True)
            (dest / rel).write_bytes(data)
        return common.Result(0)
    return run


MAINTENANCE = {"hpcustomcapcomp.inf": b"[SourceDisksFiles]\nHpAgent.exe=1,Agent\n",
               "hpcustomcapcomp.cat": b"catalog",
               "Agent/HpAgent.exe": b"MZ agent", "Agent/lang/cs-CZ/HpAgent.mui": b"mui"}


def test_cabinet_keeps_its_folders(runner, windows, tmp_path):
    runner.available.add("tar")
    runner.on("tar", fake_tar(MAINTENANCE))
    cab = tmp_path / "Maintenance.cab"
    cab.write_bytes(b"MSCF....")
    (tmp_path / "out").mkdir()
    installer.unpack_package(cab, "cab", tmp_path / "out")
    assert sorted(str(p.relative_to(tmp_path / "out")).replace("\\", "/") for p in (tmp_path / "out").rglob("*")
                  if p.is_file()) == sorted(MAINTENANCE)
    assert not runner.ran("expand")


def test_expand_is_the_fallback_when_tar_is_missing_or_fails(runner, windows, tmp_path):
    def expand(cmd, env):
        (Path(cmd[3]) / "x.inf").write_bytes(b"[Version]")
        return common.Result(0)
    runner.on("expand", expand)
    cab = tmp_path / "a.cab"
    cab.write_bytes(b"MSCF")
    (tmp_path / "o1").mkdir()
    installer.unpack_package(cab, "cab", tmp_path / "o1")                 # no tar.exe
    assert (tmp_path / "o1" / "x.inf").is_file()
    runner.available.add("tar")
    runner.on("tar", lambda cmd, env: common.Result(1, "", "tar: Unsupported cabinet compression"))
    (tmp_path / "o2").mkdir()
    installer.unpack_package(cab, "cab", tmp_path / "o2")
    assert (tmp_path / "o2" / "x.inf").is_file() and len(runner.ran("expand")) == 2


def test_update_parts_share_one_tree_so_inf_paths_resolve(runner, windows, tmp_path):
    """The .inf in the cabinet names Agent\\HpAgent.exe; a loose part of the same update sits in
    Agent\\ too. Both must end up below one root, as Windows Update lays them out."""
    runner.available.add("tar")
    runner.on("tar", fake_tar(MAINTENANCE))
    payload = tmp_path / "payload"
    (payload / "Agent").mkdir(parents=True)
    (payload / "Maintenance.cab").write_bytes(b"MSCF....")
    (payload / "Agent" / "HpAgentConfig.xml").write_bytes(b"<x/>")
    files = sorted(f for f in payload.rglob("*") if f.is_file())
    out = installer.build_package_dir(files, payload, tmp_path / "package")
    tree = sorted(str(p.relative_to(out)).replace("\\", "/") for p in out.rglob("*") if p.is_file())
    assert tree == sorted([*MAINTENANCE, "Agent/HpAgentConfig.xml"])
    assert not any(n.startswith("cab") for n in tree)                       # no per-cabinet sub-folders any more
    assert not list(tmp_path.glob(".package-*"))                            # scratch folders removed


def test_two_parts_with_different_content_at_one_path_are_refused(runner, windows, tmp_path):
    runner.available.add("tar")
    runner.on("tar", fake_tar({"driver.inf": b"[Version] from the cabinet"}))
    payload = tmp_path / "payload"
    payload.mkdir()
    (payload / "a.cab").write_bytes(b"MSCF")
    (payload / "driver.inf").write_bytes(b"[Version] loose, different")
    with pytest.raises(InstallError, match="different files at driver.inf"):
        installer.build_package_dir(sorted(payload.iterdir()), payload, tmp_path / "package")


def test_cabinet_entries_outside_the_folder_are_refused(runner, windows, tmp_path):
    runner.available.add("tar")
    outside = tmp_path / "outside.txt"
    outside.write_text("x")

    def sneaky(cmd, env):
        dest = Path(cmd[cmd.index("-C") + 1])
        (dest / "link").symlink_to(outside)
        return common.Result(0)
    runner.on("tar", sneaky)
    (tmp_path / "a.cab").write_bytes(b"MSCF")
    (tmp_path / "o").mkdir()
    with pytest.raises(InstallError, match="unsafe entry: link"):
        installer.unpack_package(tmp_path / "a.cab", "cab", tmp_path / "o")


# -------------------------------------------------------- console output
def test_localized_tool_output_uses_the_oem_code_page():
    czech = "Systém nemůže nalézt uvedený soubor."
    assert common.decode_output(czech.encode("cp852"), oem="cp852") == czech
    assert common.decode_output(czech.encode("utf-8"), oem="cp852") == czech     # UTF-8 stays UTF-8
    assert common.decode_output(b"", oem="cp852") == "" and common.decode_output(None) == ""
    assert "�" not in common.decode_output("Žluťoučký kůň".encode("cp852"), oem="cp852")


@pytest.mark.parametrize("text", [
    "Systém nemůže nalézt uvedený soubor.",
    "Ovladač byl přidán do úložiště ovladačů.",
    "Zařízení nevyžaduje aktualizaci ovladače.",
    "Žluťoučký kůň úpěl ďábelské ódy.",
])
def test_pnputil_output_in_the_ansi_code_page_is_not_garbled(text):
    """pnputil writes redirected output in the ANSI code page (cp1250 on Czech Windows) while
    console tools use the OEM one (cp852). Either way the readable decoding wins."""
    for written in ("cp1250", "cp852"):
        assert common.decode_output(text.encode(written), oem="cp852", ansi="cp1250") == text
    garbled = text.encode("cp1250").decode("cp852")
    assert common.decode_output(text.encode("cp1250"), oem="cp852", ansi="cp1250") != garbled


def test_run_decodes_pnputil_cp1250_output(monkeypatch):
    import subprocess
    czech = "Systém nemůže nalézt uvedený soubor."
    monkeypatch.setattr(common, "oem_codepage", lambda: "cp852")
    monkeypatch.setattr(common, "ansi_codepage", lambda: "cp1250")
    monkeypatch.setattr(common, "resolve_binary", lambda name: "/bin/" + name)
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(
        a[0], 2, czech.encode("cp1250"), b""))
    out = common.run(["pnputil", "/add-driver", "x.inf"]).stdout
    assert out == czech and "SystÚm" not in out and "nem¨×e" not in out


def test_code_pages_come_from_windows_only(monkeypatch):
    monkeypatch.setattr(common, "OS_NAME", "linux")
    assert common.ansi_codepage() is None and common.oem_codepage() is None
    import ctypes
    kernel32 = type("K", (), {"GetACP": staticmethod(lambda: 1250), "GetOEMCP": staticmethod(lambda: 852)})
    monkeypatch.setattr(ctypes, "windll", type("W", (), {"kernel32": kernel32}), raising=False)
    monkeypatch.setattr(common, "OS_NAME", "windows")
    assert (common.ansi_codepage(), common.oem_codepage()) == ("cp1250", "cp852")


# ------------------------------------------------------ local-time log stamps
@pytest.fixture
def prague_time(monkeypatch):
    import time
    if not hasattr(time, "tzset"):
        pytest.skip("needs time.tzset")
    monkeypatch.setenv("TZ", "Europe/Prague")
    time.tzset()
    yield
    monkeypatch.undo()
    time.tzset()


def test_log_timestamps_are_local_time(prague_time, tmp_path):
    import datetime as dt
    from core import diagnostics
    winter = dt.datetime(2026, 11, 23, 13, 34, 2, 120000, tzinfo=dt.timezone.utc)
    assert common.local_timestamp(winter) == "2026-11-23T14:34:02.120+01:00"
    summer = dt.datetime(2026, 7, 1, 13, 0, 0, tzinfo=dt.timezone.utc)
    assert common.local_timestamp(summer).endswith("T15:00:00.000+02:00")
    # the LOG drawer shows the computer's clock, also for UTC stamps from older helper logs
    assert common.local_clock("2026-11-23T14:34:02.120+01:00") == "14:34:02"
    assert common.local_clock("2026-11-23T13:34:02.120+00:00") == "14:34:02"
    assert common.local_clock("2026-11-23T13:34:02Z") == "14:34:02"
    assert common.local_clock("garbage") == ""
    line = diagnostics.format_record({"ts": "2026-11-23T13:34:02.120+00:00", "event": "helper.step",
                                      "data": {"phase": "install", "name": "Wifi"}})
    assert line.startswith("14:34:02  ")
    # what the audit log (and so the helper's .log) writes now
    log = common.AuditLog(tmp_path / "audit.jsonl")
    log.write("test.event", n=1)
    stamp = json.loads((tmp_path / "audit.jsonl").read_text().splitlines()[-1])["ts"]
    when = dt.datetime.fromisoformat(stamp)
    assert when.utcoffset() == dt.datetime.now().astimezone().utcoffset()
    assert abs((dt.datetime.now(dt.timezone.utc) - when).total_seconds()) < 60


def test_run_decodes_with_the_oem_code_page(monkeypatch):
    import subprocess
    czech = "Systém nemůže nalézt uvedený soubor."
    monkeypatch.setattr(common, "oem_codepage", lambda: "cp852")
    monkeypatch.setattr(common, "resolve_binary", lambda name: "/bin/" + name)
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(
        a[0], 2, czech.encode("cp852"), b""))
    assert common.run(["pnputil", "/add-driver", "x.inf"]).stdout == czech


# ------------------------------------------------ live progress from the helper
def write_lines(path: Path, records, delay=0.05, partial_split=True):
    with open(path, "ab") as fh:
        for rec in records:
            line = (json.dumps(rec) + "\n").encode()
            if partial_split:                                 # a line written in two pieces
                fh.write(line[:10]); fh.flush(); time.sleep(delay)
                fh.write(line[10:])
            else:
                fh.write(line)
            fh.flush()
            time.sleep(delay)


def rec(event, **data):
    return {"ts": "2026-11-23T13:04:00", "event": event, "data": data}


def test_step_text_names_the_step_and_the_driver():
    assert engine.step_text(rec("helper.step", phase="install", index=2, total=5,
                                name="HP Inc. SoftwareComponent Driver Update")) == \
        "Installing (2/5): HP Inc. SoftwareComponent Driver Update…"
    assert engine.step_text(rec("helper.step", phase="download", index=1, total=5, name="Voice Clarity")) == \
        "Downloading through Windows Update (1/5): Voice Clarity…"
    assert engine.step_text(rec("helper.step", phase="restore", index=0, total=5, name="")) == "Creating a restore point…"
    assert engine.step_text(rec("helper.start", items=5)).startswith("Administrator approval granted")
    assert engine.step_text(rec("wua.fetch.start", update=UID)) is None


def test_tail_reads_complete_lines_as_they_are_written(tmp_path):
    log = tmp_path / "plan.log"                              # does not exist yet: UAC not answered
    got = []
    tail = engine.HelperLogTail(log, got.append, interval=0.02)
    tail.start()
    time.sleep(0.1)
    assert got == []
    write_lines(log, [rec("helper.start", items=2), rec("helper.step", phase="install", index=1, total=2, name="A")])
    deadline = time.time() + 3
    while len(got) < 2 and time.time() < deadline:
        time.sleep(0.02)
    assert [r["event"] for r in got] == ["helper.start", "helper.step"]         # while it is still running
    write_lines(log, [rec("helper.done", status="ok")], delay=0)
    tail.stop()
    assert [r["event"] for r in got][-1] == "helper.done" and tail.count == 3 and not tail.is_alive()


def test_apply_reports_progress_while_the_elevated_helper_runs(tmp_path, runner, windows, as_user, monkeypatch):
    """The window must not sit on "waiting for administrator approval" for minutes: progress
    arrives while run_elevated is still blocking, and LOG gets [admin] lines live."""
    from core import elevation
    from core.model import Device, Update
    pkg = {"id": f"windowsupdate.{UID}", "origin": "windows-update", "update_id": UID, "name": "HP Driver",
           "version": "2", "artifact": {"filename": "x.cab", "format": "dir", "acquire": "windows-update-agent",
                                        "signature": {"type": "authenticode", "target": "catalog", "subject": "x"}},
           "install": {"method": "pnputil"}}
    update = Update(Device("HP"), "HP Driver", "1", "2", "Windows Update", "", pkg, "verified")
    update.set_check("sha256", "at_install", "x")
    seen_during, progress = [], []

    def uac(argv, timeout=None):
        plan = json.loads(Path(argv[-1]).read_text())
        results = common.system_state_dir() / "results"
        results.mkdir(parents=True, exist_ok=True)
        log = results / f"{plan['plan_id']}.log"
        write_lines(log, [rec("helper.start", items=1),
                          rec("helper.step", phase="download", index=1, total=1, name="HP Driver"),
                          rec("helper.step", phase="install", index=1, total=1, name="HP Driver")])
        deadline = time.time() + 3
        while len(progress) < 3 and time.time() < deadline:
            time.sleep(0.02)
        seen_during.extend(progress)                         # what the window had before the helper exited
        write_lines(log, [rec("helper.done", status="ok")], delay=0)
        (results / f"{plan['plan_id']}.json").write_text(json.dumps(
            {"status": "ok", "items": [{"id": pkg["id"], "name": "HP Driver", "status": "installed", "detail": ""}],
             "log": [rec("helper.start", items=1)]}))
        return 0
    monkeypatch.setattr(elevation, "run_elevated", uac)
    events = []
    common.audit_log().listeners.append(events.append)
    try:
        result = engine.apply([update], engine.Context(), progress=progress.append)
    finally:
        common.audit_log().listeners.remove(events.append)
    assert result["status"] == "ok"
    assert seen_during == ["Administrator approval granted. Preparing 1 update(s)…",
                           "Downloading through Windows Update (1/1): HP Driver…", "Installing (1/1): HP Driver…"]
    forwarded = [e["event"] for e in events if e["event"].startswith("elevated.")]
    assert forwarded == ["elevated.helper.start", "elevated.helper.step", "elevated.helper.step",
                         "elevated.helper.done"]                       # each once: streamed, not replayed again


def test_window_shows_live_install_progress(tmp_path, runner, windows):
    import os
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    pytest.importorskip("PySide6")
    import gui
    app, win = gui.create(engine.Context(manifest={"packages": []}), tmp_path)
    win.on_install_progress("Installing (2/5): HP Inc. SoftwareComponent Driver Update…")
    assert win.status.text().endswith("Installing (2/5): HP Inc. SoftwareComponent Driver Update…")
    win.on_install_progress(None)                                       # anything else is ignored
    assert "Installing (2/5)" in win.status.text()
    win.close()


# -------------------------------------------- pnputil rc 2 -> Windows Update installer
def test_pnputil_file_not_found_falls_back_to_the_windows_update_installer(runner, windows, monkeypatch):
    calls = []

    def ps(cmd, env):
        calls.append(env.get("SD_UPDATE_ID"))
        return common.Result(0, json.dumps({"result": 2, "reboot": True, "error": None}))
    runner.on("powershell", ps)
    pkg = {"id": f"windowsupdate.{UID}", "update_id": UID, "name": "HP SoftwareComponent", "origin": "windows-update"}
    failed = installer.InstallResult(pkg["id"], "failed", 2, "Systém nemůže nalézt uvedený soubor.",
                                     [["pnputil", "/add-driver", "x\\*.inf", "/subdirs", "/install"]])
    res = engine._install_through_wua(pkg, failed)
    assert calls == [UID] and res.status == "reboot-required" and res.ok
    assert "after pnputil could not find a file (Systém nemůže nalézt uvedený soubor.)" in res.detail
    runner.on("powershell", lambda cmd, env: common.Result(0, json.dumps(
        {"error": "the install ended with result 4", "hresult": "0x80240022", "stage": "install"})))
    res = engine._install_through_wua(pkg, failed)
    assert res.status == "failed" and "pnputil: Systém" in res.detail and "WU_E_ALL_UPDATES_FAILED" in res.detail


def test_install_update_refuses_a_malformed_id():
    with pytest.raises(windows_update.WindowsUpdateError, match="malformed"):
        windows_update.install_update("not-a-guid")
