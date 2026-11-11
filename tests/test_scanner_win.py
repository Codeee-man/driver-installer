"""Windows scanner logic against recorded WMI data; runs on any OS."""
import json

from conftest import FIXTURES
from core import common, manifest, scanner_win
from core.model import Device

WMI = FIXTURES / "wmi"
NET_CLASS = "{4d36e972-e325-11ce-bfc1-08002be10318}"
DISPLAY_CLASS = "{4d36e968-e325-11ce-bfc1-08002be10318}"


def devices() -> dict[str, Device]:
    return {d.name: d for d in scanner_win.scan(scanner_win.FixtureWmiSource(WMI))}


def test_inventory_keeps_real_devices_and_drops_driverless_software_nodes():
    names = set(devices())
    assert names == {"Intel(R) Wi-Fi 6E AX210 160MHz", "NVIDIA GeForce RTX 4070",
                     "Realtek USB GbE Family Controller", "PCI Encryption/Decryption Controller",
                     "Legacy Capture Filter"}


def test_hardware_ids_class_guid_and_version_are_extracted():
    wifi = devices()["Intel(R) Wi-Fi 6E AX210 160MHz"]
    assert wifi.hardware_ids[:2] == ["pci:8086:2725", "pci:8086:2725:8086:0024"]
    assert r"raw:pci\ven_8086&dev_2725&subsys_00248086" in wifi.hardware_ids
    assert wifi.class_guid == NET_CLASS                 # upper-case GUID in WMI is normalised
    assert wifi.driver_version == "22.250.1.2"
    assert wifi.inf == "oem42.inf" and wifi.kind == "net" and wifi.signed is True


def test_signed_driver_join_is_case_insensitive_on_pnp_device_id():
    # the fixture's Win32_PnPSignedDriver.DeviceID differs in case from Win32_PnPEntity.PNPDeviceID
    assert devices()["Intel(R) Wi-Fi 6E AX210 160MHz"].driver_version


def test_system_driver_join_gives_sys_path_and_state():
    devs = devices()
    assert devs["NVIDIA GeForce RTX 4070"].driver == "nvlddmkm"
    assert devs["NVIDIA GeForce RTX 4070"].driver_file.endswith("nvlddmkm.sys")
    assert any("Stopped" in n for n in devs["Realtek USB GbE Family Controller"].notes)


def test_all_three_wmi_date_formats():
    devs = devices()
    assert devs["Intel(R) Wi-Fi 6E AX210 160MHz"].driver_date == "2023-09-12"     # /Date(ms)/
    assert devs["NVIDIA GeForce RTX 4070"].driver_date == "2023-08-08"            # CIM_DATETIME
    assert devs["Realtek USB GbE Family Controller"].driver_date == "2022-05-11"  # ISO
    assert scanner_win.parse_wmi_date(None) == "" and scanner_win.parse_wmi_date("nonsense") == ""


def test_problem_device_and_unsigned_driver_are_flagged():
    devs = devices()
    broken = devs["PCI Encryption/Decryption Controller"]
    assert broken.driver_version == "" and "problem code 28: no driver installed" in broken.notes
    assert broken.hardware_ids[0] == "pci:1022:15e2"
    legacy = devs["Legacy Capture Filter"]                # HardwareID arrives as a bare string here
    assert legacy.signed is False and "installed driver is NOT signed" in legacy.notes
    assert r"raw:root\legacycap" in legacy.hardware_ids


def test_powershell_source_parses_array_and_single_object(runner, windows):
    rows = json.loads((WMI / "Win32_SystemDriver.json").read_text())
    runner.on("powershell", common.Result(0, json.dumps(rows)))
    assert len(scanner_win.PowerShellWmiSource().query("Win32_SystemDriver")) == 4
    runner.on("powershell", common.Result(0, json.dumps(rows[0])))       # ConvertTo-Json of one row
    assert scanner_win.PowerShellWmiSource().query("Win32_SystemDriver") == [rows[0]]
    runner.on("powershell", common.Result(1, "", "Access denied"))
    assert scanner_win.PowerShellWmiSource().query("Win32_SystemDriver") == []


def _pkg(pid, hwid, version, **extra):
    return {"id": pid, "name": pid, "vendor": "v", "category": "driver", "version": version,
            "platform": {"os": "windows", "arch": ["x86_64"]}, "hardware_ids": [hwid],
            "artifact": {"url": "https://example.invalid/a.zip", "filename": "a.zip", "size": 1, "sha256": "0" * 64,
                         "format": "zip", "signature": {"type": "authenticode", "subject": "O=X", "target": "catalog"}},
            "install": {"method": "pnputil", "reboot_required": False},
            "upstream": {"source": "vendor", "reference_url": "https://example.invalid"}, **extra}


def test_driver_matching_by_hardware_id_version_and_class(windows):
    packages = [
        _pkg("wifi.newer", "pci:8086:2725", "23.60.1.2", class_guid=NET_CLASS),
        _pkg("gpu.same", "pci:10de:2786", "31.0.15.3623"),                     # already installed
        _pkg("gpu.older", "pci:10de:2786", "31.0.15.2000"),                    # downgrade
        _pkg("gpu.wrongclass", "pci:10de:2786", "40.0.0.1", class_guid=NET_CLASS),
        _pkg("gpu.newer", "pci:10de:2786", "32.0.15.6094", class_guid=DISPLAY_CLASS),
        _pkg("crypto.missing", "pci:1022:15e2", "1.0.0.0"),                    # device has no driver at all
        _pkg("usb.stepping", "usb:0bda:8153", "11.0.0.0", min_installed_version="10.60"),
        _pkg("other.hw", "pci:dead:beef", "9.9"),
    ]
    for p in packages:
        manifest.validate_package(p)
    found = manifest.find_updates(list(devices().values()), {"packages": packages})
    assert sorted(u.package["id"] for u in found) == ["crypto.missing", "gpu.newer", "wifi.newer"]
    wifi = next(u for u in found if u.package["id"] == "wifi.newer")
    assert (wifi.installed, wifi.available) == ("22.250.1.2", "23.60.1.2")


def test_platform_filters(windows):
    pkg = _pkg("p", "pci:8086:2725", "99.0", )
    assert manifest.applies_to_platform(pkg)
    assert not manifest.applies_to_platform(pkg, os_name="linux")
    assert not manifest.applies_to_platform(pkg, arch="aarch64")
    pkg["platform"]["min_os_build"] = 22000
    assert not manifest.applies_to_platform(pkg, os_build=19045)
    assert manifest.applies_to_platform(pkg, os_build=22631)
