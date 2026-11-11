import pytest

from core.model import compare_versions, is_newer, normalise_windows_id, parse_version


@pytest.mark.parametrize("a,b,expected", [
    ("31.0.15.3623", "31.0.15.3700", -1),      # Windows DriverVersion, last component
    ("31.0.15.3700", "31.0.15.3623", 1),
    ("22.250.1.2", "23.60.1.2", -1),           # numeric, not lexical: 250 > 60 but 22 < 23
    ("10.0.19041.1", "9.9.99999.9", 1),        # "10" must beat "9"
    ("1.2", "1.2.0", 0),                       # trailing zeros
    ("1.2.0.0", "1.2", 0),
    ("v2.8.1", "2.8.1", 0),
    ("550.120-1ubuntu1", "550.120", 0),        # distro revision ignored
    ("550.120-0ubuntu1", "550.90.07", 1),
    ("1:1.0", "2.0", 1),                       # epoch wins
    ("0xf8", "0xfa", -1),                      # microcode revisions
    ("0x10", "0x9", 1),
    ("", "1.0", -1),                           # unknown sorts lowest
    (None, None, 0),
    ("garbage", "0.0.1", -1),
])
def test_compare_versions(a, b, expected):
    assert compare_versions(a, b) == expected


def test_parse_version_shapes():
    assert parse_version("31.0.15.3623") == (0, 31, 0, 15, 3623)
    assert parse_version("  V1.0  ") == (0, 1)
    assert parse_version("0") == (0, 0)
    assert parse_version("in-kernel 6.8.0") == ()
    assert parse_version("4.2.0~rc1") == (0, 4, 2)


def test_is_newer_offers_when_installed_is_unknown():
    assert is_newer("1.0", "")
    assert is_newer("1.0", None)
    assert not is_newer("1.0", "1.0.0")
    assert not is_newer("22.250.1.2", "23.60.1.2")      # never offer a downgrade
    assert is_newer("23.60.1.2", "22.250.1.2")


def test_normalise_windows_ids():
    assert normalise_windows_id(r"PCI\VEN_8086&DEV_2725&SUBSYS_00248086&REV_1A")[:2] == \
        ["pci:8086:2725", "pci:8086:2725:8086:0024"]
    assert normalise_windows_id(r"usb\vid_0bda&pid_8153\000001")[0] == "usb:0bda:8153"
    assert normalise_windows_id(r"ACPI\PNP0C0A") == [r"raw:acpi\pnp0c0a"]
