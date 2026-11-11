"""Microsoft Update Catalog discovery against a mock catalog (real HTTP on loopback)."""
import hashlib
import json
from pathlib import Path

import pytest

import cli
import mock_http
from conftest import FIXTURES, KNOWN_BAD_SYS, authenticode_json, windows_powershell
from core import common, elevation, engine, scanner_win, trust
from core.discovery import ms_catalog
from core.model import Device
from core.security import loldrivers
from mock_http import MockCatalog

WHQL = authenticode_json(subject="CN=Microsoft Windows Hardware Compatibility Publisher, O=Microsoft Corporation, "
                                 "L=Redmond, S=Washington, C=US")
WIFI = "Intel(R) Wi-Fi 6E AX210 160MHz"


@pytest.fixture
def catalog(monkeypatch, loopback):
    server = MockCatalog()
    monkeypatch.setattr(ms_catalog, "BASE", server.base)
    monkeypatch.setattr(ms_catalog, "REQUEST_DELAY", 0)
    monkeypatch.setattr(ms_catalog, "DOWNLOAD_HOSTS", ("127.0.0.1",))
    monkeypatch.setattr(ms_catalog, "normalise_download_url", lambda url: url)     # the mock host is plain http
    monkeypatch.setattr(ms_catalog, "_windows_build", lambda: 19045)               # a Windows 10 machine
    yield server
    server.close()


def fixture_devices() -> dict[str, Device]:
    return {d.name: d for d in scanner_win.scan(scanner_win.FixtureWmiSource(FIXTURES / "wmi"))}


# ---------------------------------------------------------------- parsers
def test_parse_search_results_table():
    entries = ms_catalog.parse_search(mock_http.search_page(mock_http.ROWS["PCI\\VEN_8086&DEV_2725"]))
    assert len(entries) == 6
    newest = next(e for e in entries if e.update_id == mock_http.NEWEST_X64)
    assert (newest.title, newest.classification, newest.version) == ("Intel - Net - 23.60.1.2", "Drivers (Networking)", "23.60.1.2")
    assert newest.last_updated == "2026-10-20" and newest.size == 48211968
    assert "upgrade & servicing drivers" in newest.products               # entities decoded


def test_parse_search_no_results_and_unknown_layout():
    assert ms_catalog.parse_search(mock_http.search_page([])) == []
    with pytest.raises(ms_catalog.CatalogError, match="unexpected search page layout"):
        ms_catalog.parse_search("<html><body><h1>Please verify you are human</h1></body></html>")


def test_parse_details_and_download_dialog():
    info = ms_catalog.parse_details(mock_http.details_page(mock_http.USB_NIC))
    assert info.architectures == ["x86_64", "x86"] and info.provider == "Realtek" and info.version_date == "2024-06-02"
    assert info.hardware_ids == ["USB\\VID_0BDA&PID_8153&REV_3100", "USB\\VID_0BDA&PID_8153"]
    sha1_b64, sha256_b64 = "2jmj7l5rSw0yVb/vlWAYkK/YBwk=", "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
    files = ms_catalog.parse_download_dialog(f"""
        downloadInformation[0].files[0].url = 'http://download.windowsupdate.com/d/a.cab';
        downloadInformation[0].files[0].digest = '{sha1_b64}';
        downloadInformation[0].files[0].sha256 = '{sha256_b64}';
        downloadInformation[0].files[1].url = 'https://catalog.s.download.windowsupdate.com/d/b.cab';
        downloadInformation[0].files[1].digest = 'not base64!!';""")
    assert files[0].sha1 == "da39a3ee5e6b4b0d3255bfef95601890afd80709"      # SHA-1 of empty input
    assert files[0].sha256 == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert files[1].url.endswith("b.cab") and files[1].sha1 == ""
    assert ms_catalog.parse_download_dialog("<html>nothing here</html>") == []


def test_query_ids_are_most_specific_first_in_windows_spelling():
    wifi = fixture_devices()[WIFI]
    assert ms_catalog.query_ids(wifi) == ["PCI\\VEN_8086&DEV_2725&SUBSYS_00248086", "PCI\\VEN_8086&DEV_2725"]
    assert ms_catalog.query_ids(Device("usb", hardware_ids=["usb:0bda:8153", "raw:x"])) == ["USB\\VID_0BDA&PID_8153"]
    assert ms_catalog.query_ids(Device("acpi", hardware_ids=["raw:acpi\\pnp0c0a"])) == []


@pytest.mark.parametrize("host,ok", [
    ("download.windowsupdate.com", True), ("catalog.s.download.windowsupdate.com", True),
    ("catalog.sf.dl.delivery.mp.microsoft.com", True), ("DOWNLOAD.WINDOWSUPDATE.COM.", True),
    ("download.windowsupdate.com.evil.example", False), ("evildownload.windowsupdate.com", False),
    ("windowsupdate.com", False), ("example.org", False), ("", False),
])
def test_download_host_allowlist(host, ok):
    assert ms_catalog.is_download_host(host) is ok


def test_download_links_are_upgraded_to_https_and_foreign_hosts_refused():
    assert ms_catalog.normalise_download_url("http://download.windowsupdate.com/d/x.cab") == \
        "https://download.windowsupdate.com/d/x.cab"
    with pytest.raises(ms_catalog.CatalogError, match="unexpected host"):
        ms_catalog.normalise_download_url("https://files.example.org/x.cab")


# -------------------------------------------------------------- selection
def test_best_update_picks_the_newest_driver_that_really_fits(catalog):
    wifi = fixture_devices()[WIFI]                                         # installed: 22.250.1.2
    pkg = ms_catalog.best_update(wifi, ms_catalog.CatalogClient(), arch="x86_64", os_build=19045)
    assert pkg["update_id"] == mock_http.NEWEST_X64 and pkg["version"] == "23.60.1.2"
    # 24.0.0.0 is Windows 11 only, 23.70.0.1 is ARM64, 23.65.0.0 is for other hardware, 22.200.0.0 is older
    assert pkg["origin"] == "ms-catalog" and pkg["id"] == f"mscatalog.{mock_http.NEWEST_X64}"
    assert pkg["release_date"] == "2026-10-20" and pkg["platform"] == {"os": "windows", "arch": ["x86_64"]}
    assert pkg["artifact"]["signature"]["subject"] == trust.MS_WHQL_SUBJECT and pkg["install"]["method"] == "pnputil"
    assert pkg["id_confirmed"] is True and pkg["hardware_ids"] == ["pci:8086:2725"]
    searches = [q["q"][0] for m, path, q in catalog.requests if path == "/Search.aspx"]
    assert searches == ["PCI\\VEN_8086&DEV_2725&SUBSYS_00248086", "PCI\\VEN_8086&DEV_2725"]   # specific first, then generic


def test_best_update_on_other_machines(catalog):
    wifi = fixture_devices()[WIFI]
    client = ms_catalog.CatalogClient()
    assert ms_catalog.best_update(wifi, client, arch="x86_64", os_build=26100)["version"] == "24.0.0.0"   # Windows 11
    assert ms_catalog.best_update(wifi, client, arch="aarch64", os_build=19045)["version"] == "23.70.0.1"
    wifi.driver_version = "24.0.0.0"
    assert ms_catalog.best_update(wifi, client, arch="x86_64", os_build=26100) is None                    # never a downgrade


def test_discover_over_a_scanned_machine(catalog):
    found = {dev.name: pkg for dev, pkg in ms_catalog.discover(list(fixture_devices().values()))}
    assert set(found) == {WIFI, "Realtek USB GbE Family Controller"}
    assert found["Realtek USB GbE Family Controller"]["version"] == "10.60.0.1"      # installed 10.50.511.2022
    events = [json.loads(line) for line in Path(common.audit_log().path).read_text().splitlines()]
    queries = [e["data"]["query"] for e in events if e["event"] == "catalog.search"]
    assert "PCI\\VEN_10DE&DEV_2786&SUBSYS_40E91458" in queries                        # every lookup is in the audit log
    assert not any(m == "POST" for m, _, _ in catalog.requests)                       # no download links fetched yet


def test_discover_raises_when_the_catalog_is_down_and_engine_turns_that_into_a_note(catalog, windows):
    catalog.fail = True
    devices = list(fixture_devices().values())
    with pytest.raises(ms_catalog.CatalogError):
        ms_catalog.discover(devices)
    ctx = engine.Context(discover=True)
    assert engine.find_all_updates(devices, {}, ctx) == []
    assert "online discovery failed" in ctx.notes[0]


# ------------------------------------------------------------ full pipeline
@pytest.fixture
def win_box(catalog, runner, windows, monkeypatch, tmp_path):
    """Windows 10 PC from the WMI fixtures, no manifest, catalog discovery on."""
    monkeypatch.setattr(scanner_win, "default_source", lambda: scanner_win.FixtureWmiSource(FIXTURES / "wmi"))
    monkeypatch.setattr(engine, "AUTO_DISCOVER", True)
    files = {"netwtw14.inf": b"[Version]\n", "netwtw14.cat": b"catalog", "Netwtw14.sys": b"MZ wifi driver"}

    def expand(cmd, env):                         # stands in for expand.exe -F:* <cab> <dir>
        for name, data in files.items():
            (Path(cmd[3]) / name).write_bytes(data)
        return common.Result(0)
    runner.on("expand", expand)
    runner.on("powershell", windows_powershell(signer=WHQL))
    return catalog, runner, files


def discovered(ctx):
    devices, upgrades = engine.scan()
    updates = engine.find_all_updates(devices, upgrades, ctx)
    return next(u for u in updates if u.device.name == WIFI), updates


def test_windows_needs_no_manifest_discovery_download_verify_install(win_box, as_admin):
    catalog, runner, _ = win_box
    ctx = engine.Context()
    update, updates = discovered(ctx)
    assert ctx.manifest is None and len(updates) == 2
    assert (update.installed, update.available, update.source) == ("22.250.1.2", "23.60.1.2", "Microsoft Update Catalog")
    engine.verify_update(update, ctx)
    assert update.status == "verified" and "catalog digest OK" in update.detail
    assert "LOLDrivers: 1 .sys file(s) clean" in update.detail
    assert update.sha256 == hashlib.sha256(catalog.cab).hexdigest() and Path(update.path).read_bytes() == catalog.cab
    form = next(q for m, path, q in catalog.requests if m == "POST")
    assert json.loads(form["updateIDs"][0])[0]["updateID"] == mock_http.NEWEST_X64
    plan = engine.dry_run_plan([update])
    assert any("LOLDrivers" in line for line in plan) and any("/subdirs /install" in line for line in plan)
    result = engine.apply([update], ctx)
    assert result["status"] == "ok" and result["items"][0]["id"] == f"mscatalog.{mock_http.NEWEST_X64}"
    args = runner.ran("pnputil")[0]
    assert args[0] == "/add-driver" and args[1].endswith("*.inf") and args[2:] == ["/subdirs", "/install"]
    checked = [e for _, _, e in runner.calls if "SD_FILE" in e]
    assert len(checked) == 1 and checked[0]["SD_FILE"].endswith("netwtw14.cat")     # WHQL catalog signature


def test_catalog_digest_mismatch_purges_the_download(win_box, as_user):
    catalog, _, _ = win_box
    ctx = engine.Context()
    update, _ = discovered(ctx)
    catalog.digest = "2jmj7l5rSw0yVb/vlWAYkK/YBwk="               # catalog claims a different SHA-1
    engine.verify_update(update, ctx)
    assert update.status == "failed" and "SHA-1 MISMATCH" in update.detail
    assert not ctx.quarantine.exists() or list(ctx.quarantine.iterdir()) == []


def test_download_from_a_non_microsoft_host_is_refused(win_box, as_user, monkeypatch):
    ctx = engine.Context()
    update, _ = discovered(ctx)
    monkeypatch.setattr(ms_catalog, "DOWNLOAD_HOSTS", ("download.windowsupdate.com",))   # the real allowlist
    engine.verify_update(update, ctx)
    assert update.status == "failed" and "unexpected host: 127.0.0.1" in update.detail


def test_helper_requires_microsoft_hardware_publisher_whatever_the_plan_claims(win_box, as_admin):
    _, runner, _ = win_box
    ctx = engine.Context()
    update, _ = discovered(ctx)
    engine.verify_update(update, ctx)
    # a compromised front end rewrites the descriptor: other signer, other method, extra command-ish fields
    update.package["artifact"]["signature"] = {"type": "delegated", "verifier": "fwupd"}
    update.package["install"] = {"method": "package-manager", "package_name": "evil", "manager": "apt-get"}
    runner.on("powershell", windows_powershell(signer=authenticode_json(subject="CN=Some Vendor, O=Some Vendor Inc")))
    result = engine.apply([update], ctx)
    assert result["status"] == "refused" and "not the pinned publisher" in result["items"][0]["detail"]
    assert trust.MS_WHQL_SUBJECT in result["items"][0]["detail"]
    assert runner.ran("pnputil") == [] and runner.ran("apt-get") == []


def test_helper_rejects_malformed_or_unverified_discovered_items(win_box, as_admin, tmp_path):
    ctx = engine.Context()
    update, _ = discovered(ctx)
    engine.verify_update(update, ctx)
    plan_path, _ = engine.write_plan([update], ctx)
    plan = json.loads(plan_path.read_text())
    good = plan["items"][0]["discovered"]
    for mutate in (lambda d: d.update(update_id="../../x"), lambda d: d["artifact"].update(sha256=""),
                   lambda d: d["artifact"].update(size=10 ** 12), lambda d: d.update(origin="somewhere-else"),
                   lambda d: d.pop("artifact")):
        bad = json.loads(json.dumps(good))
        mutate(bad)
        plan["items"] = [{"discovered": bad, "file": update.path}]
        plan_path.write_text(json.dumps(plan))
        assert engine.execute_plan(plan_path)["status"] == "refused"
    plan["items"] = [{"discovered": "not a dict", "file": update.path}]
    plan_path.write_text(json.dumps(plan))
    assert engine.execute_plan(plan_path)["status"] == "refused"
    assert win_box[1].ran("pnputil") == []


def test_blocklisted_driver_from_the_catalog_is_stopped(win_box, as_admin):
    """A WHQL-signed but known-vulnerable driver is exactly the BYOVD case."""
    _, runner, files = win_box
    files["Netwtw14.sys"] = KNOWN_BAD_SYS
    ctx = engine.Context()
    update, _ = discovered(ctx)
    engine.verify_update(update, ctx)
    assert update.status == "failed" and "SECURITY ALERT: Netwtw14.sys" in update.detail     # caught before elevation
    assert list(ctx.quarantine.iterdir()) == []
    update, _ = discovered(ctx)
    ctx.blocklist = False                                        # user-side feed unavailable: helper must catch it
    engine.verify_update(update, ctx)
    assert update.status == "verified" and "LOLDrivers check runs at install" in update.detail
    result = engine.apply([update], ctx)
    assert result["status"] == "security_alert" and runner.ran("pnputil") == []
    assert not any("SD_DESC" in e for _, _, e in runner.calls)   # no restore point was even requested


def test_cli_check_and_scan_use_discovery_without_a_manifest(win_box, as_user, capsys):
    assert cli.main(["check"]) == 1
    captured = capsys.readouterr()
    assert "22.250.1.2 -> 23.60.1.2" in captured.out and f"mscatalog.{mock_http.NEWEST_X64}" in captured.out
    assert "Looking for updates" in captured.err
    assert cli.main(["check", "--no-discover", "--quiet"]) == 0
    assert cli.main(["scan", "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert {u["source"] for u in report["updates"]} == {"Microsoft Update Catalog"}
    win_box[0].fail = True
    assert cli.main(["check"]) == 0                              # catalog down: reported, not fatal
    assert "online discovery failed" in capsys.readouterr().err


def test_manifest_takes_precedence_and_discovery_is_opt_in_next_to_it(win_box, as_user, pin, tmp_path, capsys):
    import demo
    from test_apply_flow import wifi_package
    raw, sig = pin(demo.manifest_shell([wifi_package("https://example.invalid", b"x")]))
    (tmp_path / "m.json").write_bytes(raw)
    (tmp_path / "m.json.sig").write_bytes(sig)
    assert cli.main(["scan", "--json", "--manifest", str(tmp_path / "m.json")]) == 0
    assert [u["id"] for u in json.loads(capsys.readouterr().out)["updates"]] == ["intel.wifi.ax210"]
    assert win_box[0].requests == []                              # manifest loaded: nothing sent to the catalog
    assert cli.main(["scan", "--json", "--discover", "--manifest", str(tmp_path / "m.json")]) == 0
    ids = [u["id"] for u in json.loads(capsys.readouterr().out)["updates"]]
    assert ids == ["intel.wifi.ax210", f"mscatalog.{mock_http.USB_NIC}"]     # Wi-Fi from the manifest, NIC discovered
