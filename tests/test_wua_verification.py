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
from conftest import FIXTURES, authenticode_json, windows_powershell, wua_fetch_result
from core import common, diagnostics, engine, scanner_win, verifier
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
def test_wua_hands_over_the_cab_and_the_driver_verifies_full(box, as_user):
    catalog, runner = box
    use_wua(runner, wua_fetch_result())
    update, ctx = hp_update(), engine.Context()
    engine.verify_update(update, ctx)
    assert update.status == "verified" and states(update) == {
        "sha256": "passed", "manifest": "not_applicable", "blocklist": "passed", "publisher": "passed"}
    sha = update.check("sha256").reason
    assert "downloaded by the Windows Update Agent" in sha and "302 ErrorInline.aspx (error id 2380070948)" in sha
    assert Path(update.path).parent == ctx.quarantine and Path(update.path).read_bytes().startswith(b"MSCF")
    assert [p.name for p in ctx.quarantine.iterdir()] == [Path(update.path).name]      # the WUA work dir is gone
    fetch = next(env for c, env in [(c, e) for _, c, e in runner.calls] if "SD_UPDATE_ID" in env)
    assert fetch["SD_UPDATE_ID"] == OEM


def test_admin_only_download_is_partial_with_both_reasons(box, as_user):
    _, runner = box
    use_wua(runner, DENIED)
    update, ctx = hp_update(), engine.Context()
    engine.verify_update(update, ctx)
    from ui import verification as vf
    assert update.status == "verified" and vf.level(update) == "Partial"
    assert states(update) == {"sha256": "skipped", "manifest": "not_applicable", "blocklist": "skipped",
                              "publisher": "skipped"}
    reason = update.check("sha256").reason
    assert "302 ErrorInline.aspx" in reason and "WU_E_PER_MACHINE_UPDATE_ACCESS_DENIED" in reason
    assert "before installing" in update.check("blocklist").reason
    assert update.package["artifact"]["acquire"] == "windows-update-agent" and update.path == ""
    assert "not reached" not in vf.explain(update)


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


def test_helper_refuses_a_bad_package_fetched_through_wua(box, as_user, monkeypatch):
    _, runner = box
    use_wua(runner, DENIED)
    update, ctx = hp_update(), engine.Context()
    engine.verify_update(update, ctx)
    from core import elevation
    monkeypatch.setattr(elevation, "is_admin", lambda: True)
    runner.on("powershell", windows_powershell(signer=authenticode_json(subject="CN=Not Microsoft"),
                                               wua_fetch=wua_fetch_result()))
    result = engine.apply([update], ctx)
    assert result["status"] == "refused" and "not the pinned publisher" in result["items"][0]["detail"]
    assert not runner.ran("pnputil")


def test_channel_trust_is_only_for_windows_update_items(box, as_admin):
    update = hp_update()
    update.package.update(origin="ms-catalog")
    update.package["artifact"]["acquire"] = "windows-update-agent"   # a front end cannot opt out of the hash
    with pytest.raises(engine.VerificationError, match="not downloaded and hashed"):
        engine._policy_catalog_package(update.package)


def test_failure_names_the_real_reasons_everywhere(box, as_user, tmp_path):
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


def test_fetch_package_refuses_files_outside_its_folder_and_oversized_cabs(runner, windows, tmp_path):
    outside = tmp_path / "elsewhere.cab"
    outside.write_bytes(b"MSCF")
    runner.on("powershell", lambda cmd, env: common.Result(0, json.dumps(
        {"files": [{"path": str(outside), "size": 4}], "error": None})))
    with pytest.raises(windows_update.WindowsUpdateError, match="copied no driver cabinet"):
        windows_update.fetch_package(OEM, tmp_path / "dest", 1 << 20)
    runner.on("powershell", lambda cmd, env: common.Result(0, wua_fetch_result()(env)))
    with pytest.raises(windows_update.WindowsUpdateError, match="larger than 10 bytes"):
        windows_update.fetch_package(OEM, tmp_path / "dest2", 10)
    err = windows_update.WindowsUpdateError("x", "0X80240044")
    assert err.needs_admin and not windows_update.WindowsUpdateError("x", "0x80131500").needs_admin


# ------------------------------------------------------------- popover
def test_popover_opens_on_none_and_leads_with_the_failure(box, as_user, tmp_path):
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
