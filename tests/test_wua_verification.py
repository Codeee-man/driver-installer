"""Windows Update drivers the public catalog cannot serve (DownloadDialog.aspx answers
302 -> ErrorInline.aspx), as seen live with v1.1.1 for OEM drivers such as "HP Application Driver".

Covers: the redirect is detected and named, not followed; the Windows Update Agent fallback
reaches Full when it hands over the .cab, Partial (channel trust) when only an administrator may
download it, None with the real reasons otherwise; the elevated helper downloads channel-trusted
updates itself and checks them before installing; the reasons reach the popover and the LOG."""
import json
import os
from pathlib import Path

import pytest

import mock_http
from conftest import (FIXTURES, WUA_CAB, WUA_CAB_NAMED, WUA_EXTRACTED, WUA_INSTALLER, authenticode_json,
                      windows_powershell, wua_fetch_result)
from core import common, diagnostics, engine, scanner_win, trust, verifier
from core.discovery import ms_catalog, windows_update
from core.model import Update
from mock_http import MockCatalog

OEM = "a1b2c3d4-0000-4000-8000-0000000000aa"        # what Windows Update offers; the public catalog has no copy
WHQL = authenticode_json(subject="CN=Microsoft Windows Hardware Compatibility Publisher, O=Microsoft Corporation, "
                                 "L=Redmond, S=Washington, C=US")
DENIED = wua_fetch_result(error="Exception from HRESULT: 0x80240044", hresult="0x80240044", stage="download")


@pytest.fixture
def catalog(monkeypatch, loopback):
    server = MockCatalog()
    server.not_public.add(OEM)
    monkeypatch.setattr(ms_catalog, "BASE", server.base)
    monkeypatch.setattr(ms_catalog, "REQUEST_DELAY", 0)
    monkeypatch.setattr(ms_catalog, "DOWNLOAD_HOSTS", ("127.0.0.1",))
    monkeypatch.setattr(ms_catalog, "normalise_download_url", lambda url: url)
    yield server
    server.close()


@pytest.fixture
def box(catalog, runner, windows):
    files = {"hpcustomcap.inf": b"[Version]\n", "hpcustomcap.cat": b"catalog", "HpAppDrv.sys": b"MZ hp app driver"}

    def expand(cmd, env):
        for name, data in files.items():
            (Path(cmd[3]) / name).write_bytes(data)
        return common.Result(0)
    runner.on("expand", expand)
    return catalog, runner


def use_wua(runner, fetch):
    runner.on("powershell", windows_powershell(signer=WHQL, wua_fetch=fetch))


def hp_update(url: str = "") -> Update:
    device = next(d for d in scanner_win.scan(scanner_win.FixtureWmiSource(FIXTURES / "wmi")) if d.hardware_ids)
    offer = {"UpdateID": OEM, "Title": "HP Inc. - SoftwareComponent - 1.88.4838.0",
             "DriverHardwareID": "PCI\\VEN_8086&DEV_2725", "MaxDownloadSize": 900000, "Urls": [url] if url else []}
    package = windows_update.to_package(offer, device, "1.88.4838.0")
    return Update(device, offer["Title"], "1.66.3710.0", "1.88.4838.0", "Windows Update", "", package, "pending")


def states(update):
    return {c.key: c.state for c in update.checks}


# --------------------------------------------------------- the redirect itself
def test_download_dialog_302_to_errorinline_is_named_not_followed(catalog):
    client = ms_catalog.CatalogClient()
    with pytest.raises(ms_catalog.CatalogUnavailable) as exc:
        client.files(OEM)
    assert str(exc.value) == (f"Microsoft Update Catalog returned 302 ErrorInline.aspx (error id 2380070948) for "
                              f"UpdateID {OEM}: no public download for this update")
    assert exc.value.error_id == "2380070948"
    assert not [r for r in catalog.requests if r[1] == "/ErrorInline.aspx"]       # the error page was not fetched
    method, path, form = catalog.requests[-1]
    assert (method, path) == ("POST", "/DownloadDialog.aspx")
    assert form["updateIDs"] == [f'[{{"size":0,"languages":"","uidInfo":"{OEM}","updateID":"{OEM}"}}]']
    sent = {k.lower(): v for k, v in catalog.headers[-1].items()}
    assert sent["content-type"] == "application/x-www-form-urlencoded"
    assert sent["referer"] == f"{catalog.base}/Search.aspx?q={OEM}" and sent["origin"] == catalog.base


def test_other_redirects_and_empty_dialogs_say_what_happened(monkeypatch):
    def redirect(url, data=None, headers=None, follow_redirects=True):
        assert follow_redirects is False
        raise verifier.RedirectError(url, 301, "https://www.catalog.update.microsoft.com/Maintenance.aspx")
    client = ms_catalog.CatalogClient(fetch=redirect, delay=0)
    with pytest.raises(ms_catalog.CatalogError, match=r"redirected the download dialog .*\(301 to .*Maintenance\.aspx\)"):
        client.files(OEM)
    client = ms_catalog.CatalogClient(fetch=lambda url, data=None, **kw: b"<html></html>", delay=0)
    with pytest.raises(ms_catalog.CatalogError, match=f"without a download link for UpdateID {OEM}"):
        client.files(OEM)


def test_http_fetch_raises_redirect_error_only_when_asked(catalog):
    url = f"{catalog.base}/DownloadDialog.aspx"
    body = "updateIDs=" + json.dumps([{"updateID": OEM}])
    with pytest.raises(verifier.RedirectError) as exc:
        verifier.http_fetch(url, data=body.encode(), allow_loopback_http=True, follow_redirects=False)
    assert exc.value.code == 302 and exc.value.location.endswith("/ErrorInline.aspx?id=2380070948")
    followed = verifier.http_fetch(url, data=body.encode(), allow_loopback_http=True)
    assert b"We did not find any results" in followed              # what the old code silently parsed


# ------------------------------------------------ Windows Update Agent fallback
@pytest.mark.parametrize("payload", [WUA_CAB, WUA_CAB_NAMED, WUA_EXTRACTED], ids=["cache-name", "named-cab", "extracted"])
def test_wua_payload_of_any_shape_verifies_full(box, as_admin, payload):
    """Run as administrator, the scan itself can ask the agent: a cabinet without .cab, a named
    .cab, or loose .inf/.cat/.sys files each become one driver tree, checked -> Full."""
    catalog, runner = box
    use_wua(runner, wua_fetch_result(payload=payload))
    update, ctx = hp_update(), engine.Context()
    engine.verify_update(update, ctx)
    assert update.status == "verified" and states(update) == {
        "sha256": "passed", "manifest": "not_applicable", "blocklist": "passed", "publisher": "passed"}, update.checks
    sha = update.check("sha256").reason
    assert "downloaded by the Windows Update Agent" in sha and "302 ErrorInline.aspx (error id 2380070948)" in sha
    assert "fetches it again as administrator" in sha
    art = update.package["artifact"]
    assert art["acquire"] == "windows-update-agent" and art["format"] == "dir"
    assert list(ctx.quarantine.iterdir()) == [] and update.path == ""          # the agent's folder is gone
    assert bool(runner.ran("expand")) == (payload is not WUA_EXTRACTED)           # loose files need no expand
    cats = [e["SD_FILE"] for _, _, e in runner.calls if "SD_FILE" in e]
    assert cats and all(c.endswith(".cat") for c in cats)


def test_non_driver_payload_is_none_with_the_files_named(box, as_admin):
    _, runner = box
    use_wua(runner, wua_fetch_result(payload=WUA_INSTALLER))
    update, ctx = hp_update(), engine.Context()
    engine.verify_update(update, ctx)
    reason = update.check("sha256").reason
    assert update.status == "failed" and update.check("sha256").state == "failed"
    assert "no driver package (.inf)" in reason and "HPSetup.exe (16 bytes)" in reason
    assert list(ctx.quarantine.iterdir()) == []


def test_unprivileged_scan_does_not_ask_the_agent_and_defers_the_checks_to_the_installer(box, as_user):
    """Without admin rights CopyFromCache always ends in E_ACCESSDENIED after a 20-40 s download:
    the scan does not try. The checks are "checked by the installer" (AT_INSTALL), which counts
    as Full because the elevated installer refuses the update unless all of them pass."""
    _, runner = box
    use_wua(runner, wua_fetch_result(error="must not be asked"))
    update, ctx = hp_update(), engine.Context()
    engine.verify_update(update, ctx)
    from ui import verification as vf
    assert not [e for _, _, e in runner.calls if "SD_UPDATE_ID" in e]                  # no agent call at all
    assert update.status == "verified" and vf.level(update) == "Full"
    assert states(update) == {"sha256": "at_install", "manifest": "not_applicable", "blocklist": "at_install",
                              "publisher": "at_install"}
    assert "302 ErrorInline.aspx" in update.check("sha256").reason
    assert "before pnputil runs" in update.check("blocklist").reason
    assert update.package["artifact"]["acquire"] == "windows-update-agent" and update.path == ""
    text = vf.explain(update)
    assert "» LOLDrivers BYOVD check: checked by the installer before installing" in text
    assert vf.missing(update) == []


def test_admin_denied_by_the_agent_is_also_deferred_with_its_reason(box, as_admin):
    _, runner = box
    use_wua(runner, DENIED)
    update = hp_update()
    engine.verify_update(update, engine.Context())
    assert states(update)["sha256"] == "at_install"
    assert "WU_E_PER_MACHINE_UPDATE_ACCESS_DENIED" in update.check("sha256").reason


def test_helper_downloads_a_channel_trusted_update_and_checks_it_before_installing(box, as_user, monkeypatch):
    _, runner = box
    use_wua(runner, DENIED)
    update, ctx = hp_update(), engine.Context()
    engine.verify_update(update, ctx)                               # Partial: nothing to inspect yet
    from core import elevation
    monkeypatch.setattr(elevation, "is_admin", lambda: True)
    use_wua(runner, wua_fetch_result())                             # the administrator may download it
    result = engine.apply([update], ctx)
    assert result["status"] == "ok" and result["items"][0]["id"] == f"windowsupdate.{OEM}"
    assert runner.ran("pnputil") and runner.ran("expand")
    cats = [e["SD_FILE"] for _, _, e in runner.calls if "SD_FILE" in e]
    assert cats and all(c.endswith("hpcustomcap.cat") for c in cats)         # WHQL signer checked in the helper


@pytest.mark.parametrize("signer, ok", [
    (authenticode_json(subject="CN=HP Inc., O=HP Inc., L=Palo Alto, S=California, C=US"), True),     # OEM signer
    (authenticode_json(subject='CN="WDKTestCert cloudtest,133775"', status="UnknownError"), True),   # Insider flight
    (authenticode_json(subject="CN=HP Inc.", status="HashMismatch"), False),                          # tampered
    (authenticode_json(subject="", status="NotSigned"), False),                                       # unsigned
], ids=["oem", "flight-signed", "hash-mismatch", "unsigned"])
def test_helper_signer_policy_for_packages_it_received_from_windows_update(box, as_user, monkeypatch, signer, ok):
    _, runner = box
    ups, ctx = deferred(box)
    from core import elevation
    monkeypatch.setattr(elevation, "is_admin", lambda: True)
    runner.on("powershell", windows_powershell(signer=signer, wua_fetch=wua_fetch_result()))
    seen = []
    common.audit_log().listeners.append(seen.append)
    try:
        result = engine.apply(ups, ctx)
    finally:
        common.audit_log().listeners.remove(seen.append)
    if ok:
        assert result["status"] == "ok" and runner.ran("pnputil")
        if "UnknownError" in signer:
            (warn,) = [r for r in seen if r["event"] == "signature.wua_untrusted_root"]
            assert "WDKTestCert" in warn["data"]["signer"] and "Windows enforces driver signing" in warn["data"]["note"]
    else:
        assert result["status"] == "refused" and not runner.ran("pnputil")
        assert "Authenticode check failed for hpcustomcap.cat: status" in result["items"][0]["detail"]


def test_loldrivers_still_stops_a_windows_update_package(box, as_user, monkeypatch):
    from core.security import loldrivers
    _, runner = box
    ups, ctx = deferred(box)
    from core import elevation
    monkeypatch.setattr(elevation, "is_admin", lambda: True)
    use_wua(runner, wua_fetch_result(payload=WUA_EXTRACTED))
    bad = __import__("hashlib").sha256(WUA_EXTRACTED["hpappdrv/x64/HpAppDrv.sys"]).hexdigest()
    blocklist = loldrivers.Blocklist()
    blocklist.add("SHA256", bad, loldrivers.BlockEntry("lol-1", "vulnerable driver", "HpAppDrv.sys"))
    monkeypatch.setattr(loldrivers, "fetch", lambda *a, **k: blocklist)
    result = engine.apply(ups, ctx)
    assert result["status"] == "security_alert" and not runner.ran("pnputil")


def test_channel_trust_is_only_for_windows_update_items(box, as_admin):
    update = hp_update()
    update.package.update(origin="ms-catalog")
    update.package["artifact"]["acquire"] = "windows-update-agent"   # a front end cannot opt out of the hash
    with pytest.raises(engine.VerificationError, match="not downloaded and hashed"):
        engine._policy_catalog_package(update.package)


def test_failure_names_the_real_reasons_everywhere(box, as_admin, tmp_path):
    _, runner = box
    use_wua(runner, wua_fetch_result(error="Windows Update no longer offers this update to this PC",
                                     hresult="0x80131500", stage="search"))
    update, ctx = hp_update(), engine.Context()
    seen = []
    common.audit_log().listeners.append(seen.append)
    try:
        engine.verify_update(update, ctx)
    finally:
        common.audit_log().listeners.remove(seen.append)
    assert update.status == "failed"
    sha = update.check("sha256")
    assert sha.state == "failed" and "302 ErrorInline.aspx" in sha.reason and "no longer offers" in sha.reason
    for key in ("blocklist", "publisher"):
        assert update.check(key).reason.startswith("not reached: SHA-256 integrity failed (could not get the file:")
    lines = "\n".join(diagnostics.format_record(r) for r in seen if r["event"] == "verify.failed")
    assert "verification FAILED at SHA-256 integrity" in lines and "ErrorInline.aspx" in lines
    assert any(r["event"] == "catalog.redirect" for r in seen)


def test_wua_url_is_still_used_before_asking_the_agent(box, as_user):
    catalog, runner = box
    use_wua(runner, wua_fetch_result(error="must not be asked"))
    update = hp_update(url=f"{catalog.base}{catalog.download_host_path}")
    engine.verify_update(update, engine.Context())
    assert update.status == "verified" and states(update)["sha256"] == "skipped"    # no published digest
    assert not [e for _, _, e in runner.calls if "SD_UPDATE_ID" in e]


def test_fetch_payload_returns_only_real_files_inside_its_folder(runner, windows, tmp_path):
    dest = tmp_path / "dest"
    outside = tmp_path / "elsewhere.cab"
    outside.write_bytes(b"MSCF")

    def lying(cmd, env):                                    # the script's list is not trusted
        (Path(env["SD_DEST"]) / "real.cab").write_bytes(b"MSCF....")
        return common.Result(0, json.dumps({"files": [{"path": str(outside), "size": 4}], "error": None}))
    runner.on("powershell", lying)
    assert [f.name for f in windows_update.fetch_payload(OEM, dest, 1 << 20)] == ["real.cab"]
    runner.on("powershell", lambda cmd, env: common.Result(0, json.dumps({"files": [], "error": None})))
    with pytest.raises(windows_update.WindowsUpdateError, match="copied no files"):
        windows_update.fetch_payload(OEM, tmp_path / "empty", 1 << 20)
    runner.on("powershell", lambda cmd, env: common.Result(0, wua_fetch_result()(env)))
    with pytest.raises(windows_update.WindowsUpdateError, match="larger than 10 bytes"):
        windows_update.fetch_payload(OEM, tmp_path / "dest2", 10)
    err = windows_update.WindowsUpdateError("x", "0X80240044")
    assert err.needs_admin and not windows_update.WindowsUpdateError("x", "0x80131500").needs_admin
    assert windows_update.WindowsUpdateError("x", "0x80070005").needs_admin


# ------------------------------------------------------------- popover
def test_popover_opens_on_none_and_leads_with_the_failure(box, as_admin, tmp_path):
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    pytest.importorskip("PySide6")
    from PySide6.QtWidgets import QLabel
    import gui
    from ui.models import COL_VERIFY, HelpRole
    from ui.popover import ChecksPopover
    _, runner = box
    use_wua(runner, wua_fetch_result(error="Windows Update no longer offers this update to this PC", stage="search"))
    update = hp_update()
    engine.verify_update(update, engine.Context())
    app, win = gui.create(engine.Context(manifest={"packages": []}), tmp_path)
    win.model.load([update.device], [update])
    assert win.model.index(0, COL_VERIFY).data(HelpRole)                 # (?) is offered on a None row
    pop = ChecksPopover(win, update)
    texts = [w.text() for w in pop.findChildren(QLabel)]
    assert texts[1].startswith("Failed: SHA-256 integrity: could not get the file: Microsoft Update Catalog "
                               "returned 302 ErrorInline.aspx")
    assert any("not reached: SHA-256 integrity failed" in t for t in texts)
    assert not any(t == "not reached: an earlier step failed" for t in texts)
    pop.close()
    win.close()


# ------------------------------------------- elevated install of deferred (Partial) items
MS_WINDOWS = authenticode_json(subject="CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US")


def deferred(box, n=1):
    """Windows Update items as an unprivileged scan leaves them: nothing downloaded, checks at install."""
    catalog, runner = box
    use_wua(runner, wua_fetch_result(error="the scan must not ask the agent"))
    ups, ctx = [], engine.Context()
    for i in range(n):
        u = hp_update()
        if i:
            uid = f"a1b2c3d4-0000-4000-8000-0000000000{i:02d}"
            catalog.not_public.add(uid)
            u.package.update(update_id=uid, id=f"windowsupdate.{uid}")
        engine.verify_update(u, ctx)
        from ui import verification as vf
        assert vf.level(u) == "Full" and u.check("blocklist").state == "at_install"
        ups.append(u)
    return ups, ctx


@pytest.mark.parametrize("payload", [WUA_CAB, WUA_EXTRACTED], ids=["cab", "extracted"])
def test_elevated_helper_installs_deferred_items_from_any_payload(box, as_user, monkeypatch, payload):
    _, runner = box
    ups, ctx = deferred(box)
    from core import elevation
    monkeypatch.setattr(elevation, "is_admin", lambda: True)
    use_wua(runner, wua_fetch_result(payload=payload))
    result = engine.apply(ups, ctx)
    assert result["status"] == "ok", result
    (args,) = runner.ran("pnputil")
    assert args[0] == "/add-driver" and args[1].endswith("*.inf") and args[-1] == "/install" and "/subdirs" in args
    assert any(e["event"] == "helper.wua_acquired" and e["data"]["infs"] for e in result["log"])


def test_microsofts_own_drivers_from_windows_update_are_accepted(box, as_user, monkeypatch):
    """Voice Clarity and other Microsoft drivers are signed "Microsoft Windows", not by the
    hardware publisher: accepted for Windows Update items, still refused for catalog-only ones."""
    _, runner = box
    ups, ctx = deferred(box)
    from core import elevation
    monkeypatch.setattr(elevation, "is_admin", lambda: True)
    runner.on("powershell", windows_powershell(signer=MS_WINDOWS, wua_fetch=wua_fetch_result()))
    assert engine.apply(ups, ctx)["status"] == "ok"
    with pytest.raises(engine.VerificationError, match="not the pinned publisher"):
        verifier.verify_catalogs(_cat_dir(), trust.MS_WHQL_SUBJECT)


def _cat_dir():
    import tempfile
    d = Path(tempfile.mkdtemp())
    (d / "x.cat").write_bytes(b"catalog")
    return d


def test_refusals_as_administrator_reach_the_log_and_every_row_has_a_reason(box, as_user, monkeypatch):
    """The real round trip: the unprivileged process writes the plan, "UAC" runs the helper,
    every item is refused. The reasons are in the result, and the helper's events are replayed
    into this process's log (what the LOG drawer shows), marked as elevated."""
    _, runner = box
    ups, ctx = deferred(box, n=3)
    from core import elevation
    runner.on("powershell", windows_powershell(signer=authenticode_json(subject="CN=HP Inc.", status="HashMismatch"),
                                               wua_fetch=wua_fetch_result()))

    def uac(argv, timeout=None):
        monkeypatch.setattr(elevation, "is_admin", lambda: True)
        try:
            engine.execute_plan(Path(argv[-1]))
        finally:
            monkeypatch.setattr(elevation, "is_admin", lambda: False)
        return 2
    monkeypatch.setattr(elevation, "run_elevated", uac)
    seen = []
    common.audit_log().listeners.append(seen.append)
    try:
        result = engine.apply(ups, ctx)
    finally:
        common.audit_log().listeners.remove(seen.append)
    assert result["status"] == "refused" and len(result["items"]) == 3
    for item in result["items"]:
        assert item["status"] == "refused" and item["name"].startswith("HP Inc.")
        assert item["detail"].startswith("verification before installing: Authenticode check failed")
    assert "nothing was installed (HP Inc." in result["detail"]
    forwarded = [r for r in seen if r["event"].startswith("elevated.")]
    events = [r["event"] for r in forwarded]
    assert events[0] == "elevated.helper.start" and events[-1] == "elevated.helper.done"
    assert events.count("elevated.helper.refused") == 3 and "elevated.wua.fetch.done" in events
    lines = "\n".join(diagnostics.format_record(r) for r in forwarded)
    assert "[admin]" in lines and "verification before installing" in lines
    assert all(diagnostics.wants(e) for e in events)


def test_a_crashed_helper_still_leaves_its_log(box, as_user, monkeypatch):
    _, runner = box
    ups, ctx = deferred(box)
    from core import elevation

    def crash(argv, timeout=None):
        plan = json.loads(Path(argv[-1]).read_text())
        out = common.system_state_dir() / "results"
        out.mkdir(parents=True, exist_ok=True)
        (out / f"{plan['plan_id']}.log").write_text(json.dumps(
            {"ts": "2026-11-20T13:04:00", "event": "wua.fetch.failed",
             "data": {"update": OEM, "stage": "copy", "hresult": "0x80070005", "error": "denied"}}) + "\n")
        return 3
    monkeypatch.setattr(elevation, "run_elevated", crash)
    seen = []
    common.audit_log().listeners.append(seen.append)
    try:
        result = engine.apply(ups, ctx)
    finally:
        common.audit_log().listeners.remove(seen.append)
    assert result["status"] == "failed" and "exited with code 3 and left no result" in result["detail"]
    assert [r["event"] for r in seen if r["event"].startswith("elevated.")] == ["elevated.wua.fetch.failed"]


def test_window_shows_why_each_item_was_blocked(box, as_user, tmp_path):
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    pytest.importorskip("PySide6")
    import gui
    from PySide6.QtCore import Qt
    from ui.models import COL_STATUS, BadgeRole
    _, runner = box
    ups, _ = deferred(box, n=2)
    app, win = gui.create(engine.Context(manifest={"packages": []}), tmp_path)
    win.model.load([u.device for u in ups], ups)
    reason = "verification before installing: Authenticode check failed for hpcustomcap.cat: signer 'CN=x'"
    win.install_done({"status": "refused", "detail": "no item passed verification, nothing was installed",
                      "items": [{"id": engine.update_key(u), "name": u.name, "status": "refused", "detail": reason}
                                for u in ups]})
    app.processEvents()
    assert win.model.index(0, COL_STATUS).data(BadgeRole)[0] == "Blocked"
    assert win.model.index(0, COL_STATUS).data(Qt.ToolTipRole) == reason
    assert "2 blocked" in win.status.text() and "Authenticode check failed" in win.status.text()
    assert win.btn_log.isChecked() and reason in win.log.toPlainText()
    win.close()

