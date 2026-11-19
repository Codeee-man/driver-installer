"""Windows Update Agent discovery, catalog hardware-ID fallback with skip reasons, the PowerShell
environment fix, --debug output, and the install script's permission rules."""
import json
import re
import sys
from pathlib import Path

import pytest

import cli
from conftest import FIXTURES, windows_powershell
from core import common, diagnostics, engine, scanner_win, verifier
from core.discovery import ms_catalog, windows_update
from core.model import Device, normalise_windows_id

ROOT = Path(__file__).resolve().parents[1]
WIFI_ID = "PCI\\VEN_8086&DEV_2725&SUBSYS_00248086"
UID = "0f3a1c2e-6b7d-4e8f-9a01-23456789abcd"


def wua_result(updates=(), policy=None, error=None, code=2):
    return json.dumps({"policy": policy, "updates": list(updates), "error": error, "resultCode": code})


def wua_update(title="Intel net Driver Update (24.40.0.4)", hwid=WIFI_ID, uid=UID, urls=None):
    return {"UpdateID": uid, "Title": title, "DriverHardwareID": hwid, "DriverClass": "Net",
            "DriverProvider": "Intel", "DriverManufacturer": "Intel Corporation", "DriverModel": "Intel(R) Wi-Fi 6E AX210",
            "DriverVerDate": "2026-04-02", "MaxDownloadSize": 24467933,
            "Urls": urls if urls is not None else ["http://download.windowsupdate.com/d/msdownload/update/driver/drvs/2026/04/x_2a7b.cab"]}


def devices():
    return list(scanner_win.scan(scanner_win.FixtureWmiSource(FIXTURES / "wmi")))


# ------------------------------------------------------------- PowerShell
def test_windows_powershell_never_inherits_psmodulepath(runner, windows, monkeypatch):
    """Real-runner finding: PowerShell 7's PSModulePath breaks Get-AuthenticodeSignature in 5.1."""
    monkeypatch.setenv("PSModulePath", r"C:\Program Files\PowerShell\7\Modules")
    runner.on("powershell", common.Result(0, "{}"))
    common.powershell("Get-Date")
    assert runner.unset == [("powershell", ("PSModulePath",))]


def test_run_drops_unset_variables_case_insensitively(monkeypatch, tmp_path):
    import subprocess
    seen = {}
    monkeypatch.setenv("PSMODULEPATH", "x")
    monkeypatch.setattr(common, "resolve_binary", lambda name: "/bin/true")
    monkeypatch.setattr(subprocess, "run", lambda argv, **kw: seen.update(kw["env"]) or subprocess.CompletedProcess(argv, 0, "", ""))
    common.run(["true"], unset=("PSModulePath",))
    assert not any(k.upper() == "PSMODULEPATH" for k in seen)


def test_powershell_clixml_errors_become_readable():
    raw = ('#< CLIXML\r\n<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04"><S S="Error">'
           "Get-AuthenticodeSignature : The 'Get-AuthenticodeSignature' command was found in the module_x000D__x000A_"
           "'Microsoft.PowerShell.Security', but the module could not be loaded.</S></Objs>")
    text = common.clean_powershell_error(raw)
    assert "CLIXML" not in text and "<S" not in text and "_x000D_" not in text
    assert "module 'Microsoft.PowerShell.Security', but the module could not be loaded" in text


def test_authenticode_failure_reason_is_clean(runner, windows, tmp_path):
    runner.on("powershell", common.Result(1, "", '#< CLIXML\n<Objs><S S="Error">Access is denied._x000D__x000A_</S></Objs>'))
    with pytest.raises(common.VerificationError, match=r"status Unknown Access is denied\.$"):
        verifier.verify_authenticode(tmp_path / "x.cat", "O=Microsoft Corporation")


# ------------------------------------------------------- Windows Update
def test_search_parses_updates_policy_and_errors(runner, windows):
    runner.on("powershell", windows_powershell(wua=wua_result([wua_update()])))
    data = windows_update.search()
    assert data["updates"][0]["UpdateID"] == UID and data["resultCode"] == 2
    call = next(c for c in runner.calls if "SD_CRITERIA" in c[2])
    assert call[2]["SD_CRITERIA"] == "IsInstalled=0 and Type='Driver' and IsHidden=0"
    runner.on("powershell", windows_powershell(wua=wua_result(error="0x8024402C")))
    with pytest.raises(windows_update.WindowsUpdateError, match="0x8024402C"):
        windows_update.search()
    for bad in ("", "not json", "[]"):
        runner.on("powershell", windows_powershell(wua=bad))
        with pytest.raises(windows_update.WindowsUpdateError):
            windows_update.search()
    runner.available.discard("powershell")
    with pytest.raises(windows_update.WindowsUpdateError, match="not available"):
        windows_update.search()


@pytest.mark.parametrize("title,version", [
    ("Intel - Net - 23.60.1.2", "23.60.1.2"), ("Intel net Driver Update (24.40.0.4)", "24.40.0.4"),
    ("Realtek Semiconductor Corp. - Extension - 10.0.22000.31274", "10.0.22000.31274"), ("NVIDIA - Display", ""),
])
def test_title_version(title, version):
    assert windows_update.title_version(title) == version


def test_offered_drivers_are_matched_to_devices_with_reasons_for_the_rest(windows):
    data = json.loads(wua_result([
        wua_update(),                                                      # AX210: 22.250.1.2 -> 24.40.0.4
        wua_update("Realtek - Net - 10.60.0.1", "USB\\VID_0BDA&PID_8153&REV_3100", "11111111-2222-3333-4444-555555555555"),
        wua_update("Intel - Net - 1.0.0.0", WIFI_ID, "22222222-2222-3333-4444-555555555555"),    # older
        wua_update("Mystery - 9.9", "PCI\\VEN_DEAD&DEV_BEEF", "33333333-2222-3333-4444-555555555555"),
        wua_update("NVIDIA - Display", "PCI\\VEN_10DE&DEV_2786&SUBSYS_40E91458", "44444444-2222-3333-4444-555555555555"),
        wua_update(uid="not-a-guid"),
    ]))
    found, notes = windows_update.discover(devices(), data)
    assert sorted((d.name, p["version"]) for d, p in found) == [("Intel(R) Wi-Fi 6E AX210 160MHz", "24.40.0.4"),
                                                                ("Realtek USB GbE Family Controller", "10.60.0.1")]
    wifi = next(p for d, p in found if p["version"] == "24.40.0.4")
    assert wifi["origin"] == "windows-update" and wifi["id"] == f"windowsupdate.{UID}" and wifi["update_id"] == UID
    assert wifi["artifact"]["url"].endswith(".cab") and wifi["artifact"]["signature"]["subject"].startswith("O=Microsoft")
    assert wifi["hardware_ids"] == ["pci:8086:2725"] and wifi["matched_hardware_id"] == WIFI_ID
    events = [json.loads(line) for line in Path(common.audit_log().path).read_text().splitlines()]
    reasons = [s["reason"] for s in next(e for e in events if e["event"] == "wua.done")["data"]["skipped"]]
    assert reasons == ["1.0.0.0 is not newer than the installed 22.250.1.2",
                       "no scanned device has hardware ID PCI\\VEN_DEAD&DEV_BEEF",
                       "no version in the update title", "malformed update id"]


def test_compatible_ids_are_part_of_the_scan(windows):
    realtek = next(d for d in devices() if d.name.startswith("Realtek"))
    assert "raw:usb\\class_ff" in realtek.hardware_ids          # CompatibleID from the WMI fixture


@pytest.mark.parametrize("policy,expected", [
    ({"ExcludeWUDriversInQualityUpdate": 1}, "not to offer drivers"),
    ({"WUServer": "http://wsus.corp:8530"}, "WSUS server (http://wsus.corp:8530)"),
    ({"DoNotConnectToWindowsUpdateInternetLocations": 1}, "may not reach Microsoft"),
])
def test_policy_explains_an_empty_list(policy, expected):
    (note,) = windows_update.policy_notes(policy)
    assert expected in note
    assert windows_update.policy_notes(None) == []


def test_engine_merges_windows_update_and_catalog_newest_wins(runner, windows, monkeypatch):
    monkeypatch.setattr(scanner_win, "default_source", lambda: scanner_win.FixtureWmiSource(FIXTURES / "wmi"))
    runner.on("powershell", windows_powershell(wua=wua_result([wua_update()], policy={"WUServer": "http://wsus"})))
    devs = devices()
    wifi = next(d for d in devs if "AX210" in d.name)
    catalog = {"origin": "ms-catalog", "id": "mscatalog.x", "name": "cat", "version": "24.50.0.1"}
    monkeypatch.setattr(scanner_win, "discover_updates", lambda d, progress=None, **kw: [(wifi, catalog)])
    ctx = engine.Context(discover=True)
    (update,) = engine.find_all_updates(devs, {}, ctx)
    assert update.package is catalog and update.source == "Microsoft Update Catalog"   # newer than WU's 24.40.0.4
    catalog["version"] = "24.40.0.4"
    (update,) = engine.find_all_updates(devs, {}, engine.Context(discover=True))
    assert update.source == "Windows Update"                                            # tie: Windows Update wins
    assert ctx.notes == []                                                              # found something: no policy note


def test_engine_reports_failures_of_each_source_separately(runner, windows, monkeypatch):
    runner.on("powershell", windows_powershell(wua=wua_result(error="0x80240440 (no internet)")))

    def down(d, progress=None, **kw):
        raise ms_catalog.CatalogError("connection refused")
    monkeypatch.setattr(scanner_win, "discover_updates", down)
    ctx = engine.Context(discover=True)
    assert engine.find_all_updates(devices(), {}, ctx) == []
    assert ctx.notes == ["Windows Update search failed: Windows Update search failed: 0x80240440 (no internet)",
                         "Microsoft Update Catalog search failed: connection refused"]


def test_empty_windows_update_result_surfaces_the_policy(runner, windows, monkeypatch):
    runner.on("powershell", windows_powershell(wua=wua_result([], policy={"ExcludeWUDriversInQualityUpdate": 1})))
    monkeypatch.setattr(scanner_win, "discover_updates", lambda d, progress=None, **kw: [])
    ctx = engine.Context(discover=True)
    engine.find_all_updates(devices(), {}, ctx)
    assert any("ExcludeWUDriversInQualityUpdate=1" in n for n in ctx.notes)


def test_windows_update_package_downloads_from_catalog_digest_else_wua_url(runner, windows, monkeypatch, tmp_path):
    dev = Device("Wi-Fi", hardware_ids=["pci:8086:2725"], driver_version="22.0")
    pkg = windows_update.to_package(wua_update(), dev, "24.40.0.4")
    from core.model import Update
    seen = {}

    def fake_download(url, dest_dir, filename, **kw):
        seen.update(url=url, sha1=kw.get("expected_sha1"))
        raise common.VerificationError("stop here")
    monkeypatch.setattr(verifier, "download_from_host", fake_download)
    monkeypatch.setattr(ms_catalog, "resolve_download", lambda p: ms_catalog.CatalogFile("https://catalog.s.download.windowsupdate.com/d/a.cab", sha1="ab" * 20))
    u = Update(dev, pkg["name"], "22.0", "24.40.0.4", "Windows Update", "", pkg)
    engine.verify_update(u, engine.Context(quarantine=tmp_path))
    assert seen == {"url": "https://catalog.s.download.windowsupdate.com/d/a.cab", "sha1": "ab" * 20}
    assert "offered by Windows Update" in u.check("manifest").reason

    def no_catalog(p):
        raise ms_catalog.CatalogError("no download link")
    monkeypatch.setattr(ms_catalog, "resolve_download", no_catalog)
    engine.verify_update(u, engine.Context(quarantine=tmp_path))
    assert seen["url"].startswith("https://download.windowsupdate.com/") and seen["sha1"] is None


def test_helper_policy_keeps_the_windows_update_identity(windows, as_admin):
    desc = {"origin": "windows-update", "update_id": UID, "name": "x", "version": "1",
            "artifact": {"sha256": "a" * 64, "size": 10}}
    pkg = engine._policy_catalog_package(desc)
    assert pkg["id"] == f"windowsupdate.{UID}" and pkg["install"]["method"] == "pnputil"
    assert pkg["artifact"]["signature"]["subject"].startswith("O=Microsoft Corporation")


# ------------------------------------------------- catalog HWID fallback
class Client:
    """Canned catalog: search results per query, details per update id."""

    def __init__(self, results, details):
        self.results, self.details_map, self.queries = results, details, []

    def search(self, q):
        self.queries.append(q)
        return self.results.get(q, [])

    def details(self, uid):
        return self.details_map[uid]


def entry(uid, version, products="Windows 10 and later drivers", classification="Drivers (Networking)"):
    return ms_catalog.CatalogEntry(uid, f"Vendor - Net - {version}", products, classification, "2026-01-01", version, 1)


def wifi():
    ids = []
    for raw in (r"PCI\VEN_8086&DEV_2725&SUBSYS_00248086&REV_1A", r"PCI\VEN_8086&DEV_2725&SUBSYS_00248086"):
        ids += [h for h in normalise_windows_id(raw) if h not in ids]
    return Device("Wi-Fi", hardware_ids=ids, driver_version="22.0.0.0")


def test_full_hardware_id_first_then_base_when_full_finds_nothing(windows):
    base = "PCI\\VEN_8086&DEV_2725"
    client = Client({base: [entry("b" * 8 + "-0000-0000-0000-000000000000", "24.0")]},
                    {"b" * 8 + "-0000-0000-0000-000000000000": ms_catalog.CatalogDetails(["x86_64"], [base])})
    pkg = ms_catalog.best_update(wifi(), client, arch="x86_64", os_build=26100)
    assert client.queries == [WIFI_ID, base] and pkg["version"] == "24.0" and pkg["matched_hardware_id"] == base
    trace = [json.loads(l) for l in Path(common.audit_log().path).read_text().splitlines() if '"catalog.device"' in l][-1]
    steps = trace["data"]["steps"]
    assert [(s["query"], s["level"], s["results"]) for s in steps] == [(WIFI_ID, "full", 0), (base, "base", 1)]


def test_full_match_stops_the_fallback(windows):
    uid = "c" * 8 + "-0000-0000-0000-000000000000"
    client = Client({WIFI_ID: [entry(uid, "24.0")]}, {uid: ms_catalog.CatalogDetails(["x86_64"], [WIFI_ID])})
    assert ms_catalog.best_update(wifi(), client, arch="x86_64", os_build=26100)["version"] == "24.0"
    assert client.queries == [WIFI_ID]


def test_every_skipped_result_has_a_reason(windows, monkeypatch):
    monkeypatch.setattr(ms_catalog, "MAX_DETAILS", 8)
    base = "PCI\\VEN_8086&DEV_2725"
    ids = [f"{n:08x}-0000-0000-0000-000000000000" for n in range(16)]
    results = [entry(ids[0], "21.0"),                                          # older
               entry(ids[1], "24.0", products="Windows 7"),                    # wrong OS
               entry(ids[2], "24.0", classification="Updates"),                # not a driver
               entry(ids[3], "n/a"),                                           # no version
               entry(ids[4], "25.0"), entry(ids[5], "25.1")]                   # newer, but details exclude them
    results += [entry(ids[n], f"26.{n}") for n in range(6, 16)]                # 10 more, beyond MAX_DETAILS
    details = {ids[4]: ms_catalog.CatalogDetails(["aarch64"], [base]),
               ids[5]: ms_catalog.CatalogDetails(["x86_64"], ["PCI\\VEN_8086&DEV_9999"])}
    details.update({ids[n]: ms_catalog.CatalogDetails(["x86_64"], ["PCI\\VEN_8086&DEV_9999"]) for n in range(6, 16)})
    client = Client({WIFI_ID: [], base: results}, details)
    assert ms_catalog.best_update(wifi(), client, arch="x86_64", os_build=26100) is None
    rec = [json.loads(l) for l in Path(common.audit_log().path).read_text().splitlines() if '"catalog.device"' in l][-1]
    skipped = rec["data"]["steps"][1]["skipped"]
    assert skipped == {"not newer than the installed driver": 1, "not for this Windows version": 1,
                       "not a driver (Updates)": 1, "no usable version": 1,
                       "this device's hardware IDs are not in the driver's supported list": 8,
                       f"not examined (only the {ms_catalog.MAX_DETAILS} newest are checked)": 4}
    assert rec["data"]["outcome"] == "no newer driver that fits"
    lines = diagnostics.describe(rec)
    assert lines[0] == "Wi-Fi (installed 22.0.0.0): no newer driver that fits"
    assert lines[2].startswith("  PCI\\VEN_8086&DEV_2725 (base): 16 results, 12 candidate(s); skipped: 8 this device's")


# ------------------------------------------------------------- --debug
def test_debug_prints_each_discovery_step(runner, windows, monkeypatch, capsys):
    monkeypatch.setattr(scanner_win, "default_source", lambda: scanner_win.FixtureWmiSource(FIXTURES / "wmi"))
    runner.on("powershell", windows_powershell(wua=wua_result([], policy={"ExcludeWUDriversInQualityUpdate": 1})))
    monkeypatch.setattr(ms_catalog, "discover", lambda devs, client=None, progress=None, **kw: (
        common.audit("catalog.start", devices=len(devs), searchable=3, not_searchable=2, os_build=26100, arch="x86_64"),
        common.audit("catalog.device", device="Wi-Fi", installed="22.0", outcome="no newer driver that fits",
                     steps=[{"query": WIFI_ID, "level": "full", "results": 0, "skipped": {}}]), [])[-1])
    assert cli.main(["check", "--discover", "--debug"]) == 0
    err = capsys.readouterr().err
    assert "WMI: 7 PnP entities, 5 devices with a driver or a problem" in err
    assert "Windows Update: search succeeded, 0 driver(s) offered, 0 matched to a scanned device" in err
    assert "note: policy ExcludeWUDriversInQualityUpdate=1" in err
    assert "5 devices scanned, 3 with a PCI/USB hardware ID" in err
    assert f"{WIFI_ID} (full): 0 results" in err
    assert cli.main(["check", "--discover"]) == 0 and "catalog.device" not in capsys.readouterr().err   # quiet without --debug


# ------------------------------------------------------- install script
PS1 = (ROOT / "tools" / "install_helper.ps1").read_text()


def test_install_script_grants_exactly_admins_system_full_and_users_read_execute():
    grants = re.findall(r"icacls \$path /inheritance:r /grant:r (.+?) \| Out-Null", PS1)
    assert grants == ["'*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX'"]
    assert "/inheritance:r" in PS1 and "Everyone" not in PS1 and "S-1-1-0" not in PS1


def test_install_script_unblocks_resets_and_verifies():
    source = PS1[PS1.index("# ---- Source checkout"):]
    assert "Release folder" not in PS1                      # releases use DriverInstaller-Setup.exe
    assert "Set-AdminOnlyAcl $dest" in source and "Remove-DownloadMark $dest" in source
    assert "Reset-ChildAcls $dest" in source and "Assert-UsersCanRun" in source
    assert "Get-ChildItem -LiteralPath $path -Recurse -File -Force | Unblock-File" in PS1
    assert "icacls (Join-Path $path '*') /reset /T /C /Q" in PS1


def test_setup_script_locks_down_the_folder_and_offers_the_path_task():
    iss = (ROOT / "packaging" / "windows" / "DriverInstaller.iss").read_text()
    assert r"DefaultDirName={autopf}\Driver Installer" in iss and "PrivilegesRequired=admin" in iss
    assert "/inheritance:r /grant:r *S-1-5-32-544:(OI)(CI)F *S-1-5-18:(OI)(CI)F *S-1-5-32-545:(OI)(CI)RX" in iss
    assert r'\*" /reset /T /C /Q' in iss and ":Zone.Identifier" in iss and "RaiseException" in iss
    assert 'Description: "Add CLI command (driver-installer) to system PATH"' in iss and "Flags: unchecked" in iss
    assert '{olddata};{app}' in iss and "RemoveFromPath" in iss and "usPostUninstall" in iss
    assert r'Name: "{autoprograms}\Driver Installer"; Filename: "{app}\DriverInstaller.exe"' in iss
    assert "runasoriginaluser" in iss                       # "Start" after setup is not elevated
    assert "SignTool=disign" in iss and "SignedUninstaller=yes" in iss


def test_spec_stays_one_folder_and_as_invoker():
    spec = (ROOT / "packaging" / "windows" / "driver-installer.spec").read_text()
    assert "exclude_binaries=True" in spec and "COLLECT(" in spec and "onefile" not in spec.lower().replace("one-file", "")
    assert "uac_admin=False" in spec and "version=VERSION_FILE" in spec
    assert spec.count("EXE(") == 1 and "console=False" in spec and 'NAME = "DriverInstaller"' in spec


def test_diagnostic_script_covers_the_known_causes_and_stays_out_of_the_zip():
    script = (ROOT / "tools" / "diagnose_windows.ps1").read_text()
    for needle in ("VerifiedAndReputablePolicyState", "Get-MpThreatDetection", "Zone.Identifier", "icacls",
                   "Get-AppLockerPolicy", "--version", ".zip"):
        assert needle in script
    import importlib.util
    spec = importlib.util.spec_from_file_location("bw", ROOT / "tools" / "build_windows.py")
    import sys
    sys.path.insert(0, str(ROOT / "tools"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.PORTABLE_TOP_LEVEL == {"DriverInstaller.exe", "_internal", "BUILD-INFO.txt"}
    assert "DriverInstaller.exe" in script and "driver-installer-gui.exe" not in script


# Products strings exactly as the live catalog showed them (Windows runner, 2026-11-18).
@pytest.mark.parametrize("products,build,ok", [
    ("Windows 11 Client, version 25H2 and later, Servicing Drivers, Windows 11 Client S, version 25H2 and later, Servicing Drivers", 26100, False),
    ("Windows 11 Client, version 25H2 and later, Servicing Drivers", 26200, True),
    ("Windows 11 Client, version 24H2 and later, Servicing Drivers, Windows 11 Client, version 24H2 and later, Upgrade & Servicing Drivers", 26100, True),
    ("Windows 10, Vibranium and later, Servicing Drivers, Windows 10 S, Vibranium and later, Servicing Drivers", 26100, True),
    ("Windows 10, Vibranium and later, Servicing Drivers", 18363, False),
    ("Windows 10, version 1809 and later, Servicing Drivers", 19045, True),
    ("Windows 11 Client, version 22H2 and later, Servicing Drivers", 19045, False),
    ("Windows 11 Client, version 22H2 and later, Servicing Drivers, Windows 10, version 1809 and later, Servicing Drivers", 19045, True),
    ("Windows 11 Client, version 26H1 and later, Servicing Drivers", 26100, False),
    ("Windows 10 and later drivers", 22631, True),
    ("Windows 7, Windows 8.1 and later drivers", 26100, False),
    ("Windows Server 2016 and Later Servicing Drivers", 26100, False),
])
def test_windows_release_in_products_is_respected(products, build, ok):
    assert ms_catalog._os_ok(products, build) is ok


def test_whole_first_page_is_examined():
    assert ms_catalog.MAX_DETAILS >= 25


def test_setup_elevates_through_uac_and_the_program_does_not():
    """Setup.exe: per-machine, elevated via the native UAC prompt before any page, no per-user
    override, no PowerShell needed after copying. DriverInstaller.exe: asInvoker, so scanning
    needs no prompt; it elevates only itself, only to install."""
    iss = (ROOT / "packaging" / "windows" / "DriverInstaller.iss").read_text()
    setup = iss[iss.index("[Setup]"):iss.index("[Messages]")]
    directives = dict(line.split("=", 1) for line in setup.splitlines() if "=" in line and not line.startswith((";", "#")))
    assert directives["PrivilegesRequired"] == "admin"
    assert directives["PrivilegesRequiredOverridesAllowed"] == ""          # no "install for me only" mode
    assert directives["CloseApplications"] == "force"                       # a running copy cannot block the ACL reset
    assert "powershell" not in iss.lower()                                   # nothing after copying can be policy-blocked
    message = next(line for line in iss.splitlines() if line.startswith("AdminPrivilegesRequired="))
    assert "UAC prompt was declined" in message and "Portable.zip" in message
    spec = (ROOT / "packaging" / "windows" / "driver-installer.spec").read_text()
    assert "uac_admin=False" in spec                                          # -> requestedExecutionLevel asInvoker
    sys.path.insert(0, str(ROOT / "tools"))
    import build_windows
    assert "asInvoker" in build_windows.check_pe_metadata.__doc__
