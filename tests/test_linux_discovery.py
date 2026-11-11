"""Linux discovery: fwupd/LVFS over D-Bus or CLI, and distro driver recommendations."""
import json
import sys
import types

import pytest

import cli
from core import common, engine, scanner_linux
from core.discovery import linux_lvfs
from core.model import Device

UBUNTU_DRIVERS = """\
== /sys/devices/pci0000:00/0000:00:01.0/0000:01:00.0 ==
modalias : pci:v000010DEd00002684sv00001043sd000088E2bc03sc00i00
vendor   : NVIDIA Corporation
model    : GeForce RTX 4090
driver   : nvidia-driver-535 - distro non-free
driver   : nvidia-driver-550 - distro non-free recommended
driver   : xserver-xorg-video-nouveau - distro free builtin

== /sys/devices/pci0000:00/0000:00:14.3 ==
modalias : pci:v00008086d00002725sv00008086sd00000024bc02sc80i00
vendor   : Intel Corporation
driver   : backport-iwlwifi-dkms - distro free
"""
MHWD_LIST = """\
> 0000:01:00.0 (0300:10de:2684) Display controller nVidia Corporation:
--------------------------------------------------------------------------------
                  NAME               VERSION          FREEDRIVER           TYPE
--------------------------------------------------------------------------------
          video-nvidia            2024.05.03               false            PCI
     video-nvidia-470xx           2023.03.23               false            PCI
           video-linux            2024.05.06                true            PCI
"""
GPU = Device("GeForce RTX 4090 (VGA compatible controller)", kind="pci", hardware_ids=["pci:10de:2684"],
             driver="nouveau", driver_version="in-kernel 6.8.0")


def test_parse_ubuntu_drivers_and_mhwd():
    assert linux_lvfs.parse_ubuntu_drivers(UBUNTU_DRIVERS) == [("pci:10de:2684", "nvidia-driver-550")]
    assert linux_lvfs.parse_mhwd(MHWD_LIST) == [("pci:10de:2684", "video-nvidia", False),
                                               ("pci:10de:2684", "video-nvidia-470xx", False),
                                               ("pci:10de:2684", "video-linux", True)]
    assert linux_lvfs.parse_ubuntu_drivers("driver : evil;rm -rf / - distro recommended") == []


def test_ubuntu_drivers_recommendation_and_already_installed(runner, linux):
    runner.available = {"ubuntu-drivers", "dpkg-query", "apt-get"}
    runner.on("ubuntu-drivers", common.Result(0, UBUNTU_DRIVERS))
    runner.on("dpkg-query", common.Result(1, "", "no packages found"))
    (rec,) = linux_lvfs.driver_recommendations([GPU])
    assert (rec.package, rec.manager, rec.tool, rec.hardware_id) == ("nvidia-driver-550", "apt-get", "ubuntu-drivers", "pci:10de:2684")
    runner.on("dpkg-query", common.Result(0, "install ok installed"))
    assert linux_lvfs.driver_recommendations([GPU]) == []


def test_mhwd_recommends_first_non_free_config_unless_installed(runner, linux):
    runner.available = {"mhwd"}
    runner.on("mhwd", lambda cmd, env: common.Result(0, MHWD_LIST if "-l" in cmd else "> No installed configs\n"))
    (rec,) = linux_lvfs.driver_recommendations([GPU])
    assert (rec.package, rec.manager) == ("video-nvidia", "mhwd")
    runner.on("mhwd", lambda cmd, env: common.Result(0, MHWD_LIST))        # -li lists it as installed
    assert linux_lvfs.driver_recommendations([GPU]) == []


@pytest.mark.parametrize("manager,probe,probe_out,package", [
    ("apt-get", "apt-cache", "nvidia-driver:\n  Installed: (none)\n  Candidate: 550.163.01-2\n", "nvidia-driver"),
    ("dnf", "dnf", "akmod-nvidia-3:550.120-1.fc41.x86_64\n", "akmod-nvidia"),
    ("pacman", "pacman", "Repository      : extra\nName            : nvidia\n", "nvidia"),
])
def test_package_manager_fallback_for_nvidia_on_nouveau(runner, linux, manager, probe, probe_out, package):
    runner.available = {manager, probe, "dpkg-query", "rpm"}
    runner.on(probe, lambda cmd, env: common.Result(0, probe_out) if cmd[1] != "-Qq" else common.Result(1))
    runner.on("dpkg-query", common.Result(1))
    runner.on("rpm", common.Result(1, "package akmod-nvidia is not installed"))
    (rec,) = linux_lvfs.driver_recommendations([GPU])
    assert (rec.package, rec.manager) == (package, manager)
    loaded = Device(GPU.name, kind="pci", hardware_ids=["pci:10de:2684"], driver="nvidia", driver_version="550.120")
    assert linux_lvfs.driver_recommendations([loaded]) == []               # proprietary driver already in use


def test_no_candidate_or_no_tools_means_no_recommendation(runner, linux):
    runner.available = {"apt-get", "apt-cache"}
    runner.on("apt-cache", common.Result(0, "nvidia-driver:\n  Installed: (none)\n  Candidate: (none)\n"))
    assert linux_lvfs.driver_recommendations([GPU]) == []
    runner.available = set()
    assert linux_lvfs.driver_recommendations([GPU]) == []


# ------------------------------------------------------------------ fwupd
class FakeBackend:
    name = "fake fwupd"

    def devices(self):
        return [{"DeviceId": "a" * 40, "Name": "System Firmware", "Vendor": "Dell", "Version": "1.8.0",
                 "Guid": ["230c8b18-8d9b-53ec-838b-6cfc0383493a"], "Plugin": "uefi_capsule", "Flags": 0b10},
                {"DeviceId": "b" * 40, "Name": "SSD 990 PRO", "Vendor": "Samsung", "Version": "4B2QJXD7",
                 "Guid": ["g1", "g2"], "Plugin": "nvme", "Flags": ["updatable", "internal"]},
                {"DeviceId": "c" * 40, "Name": "Webcam", "Version": "1.0", "Flags": 0}]

    def upgrades(self, device_id):
        assert device_id != "c" * 40, "not updatable: must not be queried"
        return {"a" * 40: [{"Version": "1.9.1", "Name": "System Firmware Update", "Checksum": "aa" * 20 + "," + "bb" * 32},
                           {"Version": "1.8.5"}]}.get(device_id, [])


def test_fwupd_inventory_lists_devices_and_newest_lvfs_release(linux):
    devices, upgrades = linux_lvfs.fwupd_inventory(FakeBackend())
    assert [d.name for d in devices] == ["System Firmware", "SSD 990 PRO", "Webcam"]
    assert devices[0].kind == "fwupd" and devices[0].hardware_ids == ["fwupd:230c8b18-8d9b-53ec-838b-6cfc0383493a"]
    assert list(upgrades) == ["a" * 40] and upgrades["a" * 40]["Version"] == "1.9.1"
    assert upgrades["a" * 40]["Checksum"] == ["aa" * 20, "bb" * 32]
    (update,) = engine.find_all_updates(devices, upgrades, engine.Context(discover=False))
    assert (update.installed, update.available, update.status, update.sha256) == ("1.8.0", "1.9.1", "delegated", "bb" * 32)


def test_dbus_backend_calls_fwupd_over_the_system_bus(monkeypatch, linux):
    calls = []

    class DBusException(Exception):
        pass

    class Interface:
        def __init__(self, proxy, name):
            calls.append(("interface", proxy, name))

        def GetDevices(self, timeout=None):
            return [{"DeviceId": "d" * 40, "Name": "Dock", "Version": "1.0", "Flags": 2, "Guid": ("g",)}]

        def GetUpgrades(self, device_id, timeout=None):
            calls.append(("GetUpgrades", device_id))
            raise DBusException("org.freedesktop.fwupd.NothingToDo")

    class SystemBus:
        def get_object(self, bus, path):
            return (bus, path)
    fake = types.SimpleNamespace(SystemBus=SystemBus, Interface=Interface, DBusException=DBusException)
    monkeypatch.setitem(sys.modules, "dbus", fake)
    backend = linux_lvfs.fwupd_backend()
    assert isinstance(backend, linux_lvfs.DbusFwupd)
    devices, upgrades = linux_lvfs.fwupd_inventory(backend)
    assert devices[0].name == "Dock" and devices[0].hardware_ids == ["fwupd:g"] and upgrades == {}
    assert calls == [("interface", ("org.freedesktop.fwupd", "/"), "org.freedesktop.fwupd"), ("GetUpgrades", "d" * 40)]


def test_cli_backend_is_the_fallback_and_scanner_uses_it(runner, linux, monkeypatch):
    monkeypatch.setitem(sys.modules, "dbus", None)                          # dbus module not installed
    runner.available = {"fwupdmgr"}
    listing = {"Devices": [{"DeviceId": "e" * 40, "Name": "UEFI dbx", "Version": "371", "Flags": ["updatable"],
                            "Guid": ["x"], "Plugin": "uefi_dbx"}]}
    updates = {"Devices": [{"DeviceId": "e" * 40, "Releases": [{"Version": "20241101", "Checksum": ["cc" * 32]}]}]}
    runner.on("fwupdmgr", lambda cmd, env: common.Result(0, json.dumps(listing if cmd[1] == "get-devices" else updates)))
    assert isinstance(linux_lvfs.fwupd_backend(), linux_lvfs.CliFwupd)
    devices, upgrades = scanner_linux.scan()
    assert any(d.name == "UEFI dbx" for d in devices) and upgrades["e" * 40]["Version"] == "20241101"
    runner.available = set()
    assert linux_lvfs.fwupd_backend() is None and linux_lvfs.fwupd_inventory() == ([], {})


# --------------------------------------------------------------- pipeline
@pytest.fixture
def ubuntu(runner, linux, monkeypatch):
    runner.available = {"ubuntu-drivers", "dpkg-query", "apt-get", "timeshift"}
    runner.on("ubuntu-drivers", common.Result(0, UBUNTU_DRIVERS))
    runner.on("dpkg-query", common.Result(1))
    monkeypatch.setattr(engine, "scan", lambda: ([GPU], {}))
    monkeypatch.setattr(scanner_linux, "scan_pci", lambda: [GPU])
    monkeypatch.setattr(engine, "AUTO_DISCOVER", True)
    return runner


def test_linux_discovers_and_installs_the_recommended_driver_without_a_manifest(ubuntu, as_admin, capsys):
    assert cli.main(["check"]) == 1
    assert "nvidia-driver-550" in capsys.readouterr().out
    assert cli.main(["update", "--all", "--apply", "-y"]) == 0
    assert ubuntu.ran("apt-get") == [["install", "-y", "--no-install-recommends", "--", "nvidia-driver-550"]]
    order = ubuntu.programs()
    assert order.index("timeshift") < order.index("apt-get")                # snapshot first
    assert order.count("ubuntu-drivers") >= 2                               # the helper asked the distro tool itself


def test_helper_installs_only_what_the_distro_tool_recommends(ubuntu, as_admin):
    ctx = engine.Context()
    (update,) = engine.find_all_updates([GPU], {}, ctx)
    assert update.package["origin"] == "linux-repo" and update.status == "delegated"
    update.package["install"]["package_name"] = "openssh-server"            # a compromised front end asks for more
    update.package["install"]["manager"] = "apt-get"
    result = engine.apply([update], ctx)
    assert result["status"] == "refused" and "not a driver package this distribution recommends" in result["items"][0]["detail"]
    update.package["install"]["package_name"] = "--allow-unauthenticated"
    assert engine.apply([update], ctx)["status"] == "refused"
    assert ubuntu.ran("apt-get") == [] and ubuntu.ran("timeshift") == []


def test_mhwd_install_command(runner, linux, as_admin, monkeypatch):
    runner.available = {"mhwd"}
    runner.on("mhwd", lambda cmd, env: common.Result(0, MHWD_LIST if "-l" in cmd else "" if "-li" in cmd else "ok"))
    monkeypatch.setattr(scanner_linux, "scan_pci", lambda: [GPU])
    ctx = engine.Context(discover=True)
    (update,) = engine.find_all_updates([GPU], {}, ctx)
    assert engine.dry_run_plan([update])[-2] == "[elevated] mhwd -i pci video-nvidia"
    assert engine.apply([update], ctx)["status"] == "ok"
    assert ["-i", "pci", "video-nvidia"] in runner.ran("mhwd")
