"""Execution engine: command construction, dry-run default, privilege gate, exit-code mapping."""
import io
import zipfile

import pytest

from conftest import driver_zip, windows_powershell
from core import common, installer
from core.common import ElevationError, InstallError
from test_scanner_win import _pkg


def win_pkg(**install):
    pkg = _pkg("intel.wifi", "pci:8086:2725", "23.60.1.2")
    pkg["artifact"]["signature"] = {"type": "authenticode", "subject": "O=Intel Corporation", "target": "catalog"}
    pkg["install"] = {"method": "pnputil", "inf_path": "x200.inf", "reboot_required": False, **install}
    return pkg


def linux_pkg(method="package-manager", fmt=None, **install):
    pkg = _pkg("vendor.pkg", "pci:10de:2684", "2.0")
    pkg["platform"]["os"] = "linux"
    pkg["install"] = {"method": method, "reboot_required": False, **install}
    if fmt:
        pkg["artifact"].update(format=fmt, filename=f"a.{fmt}", signature={"type": "delegated", "verifier": "fwupd"})
    else:
        del pkg["artifact"]
    return pkg


# ------------------------------------------------------------------ dry run
def test_dry_run_is_the_default_and_needs_no_privileges(runner, as_user, windows):
    res = installer.install(win_pkg(), None)
    assert res.status == "dry-run"
    assert res.commands == [["pnputil", "/add-driver", "<extract-dir>\\x200.inf", "/install"]]
    assert runner.calls == []                               # nothing executed


def test_dry_run_commands_for_each_method(runner, as_user, linux):
    runner.available = {"apt-get"}
    assert installer.install(linux_pkg(package_name="nvidia-driver-550"), None).commands == [
        ["apt-get", "install", "-y", "--no-install-recommends", "--", "nvidia-driver-550"]]
    assert installer.install(linux_pkg(fmt="deb"), "/q/a.deb").commands == [
        ["apt-get", "install", "-y", "--no-install-recommends", "/q/a.deb"]]
    assert installer.install(linux_pkg("fwupd", "fwupd-cab"), "/q/fw.cab").commands == [
        ["fwupdmgr", "install", "/q/fw.cab", "--assume-yes", "--no-reboot-check"]]
    assert installer.install_fwupd_device("a" * 40).commands == [
        ["fwupdmgr", "update", "a" * 40, "--assume-yes", "--no-reboot-check"]]
    assert runner.calls == []


@pytest.mark.parametrize("pm,repo,local", [
    ("dnf", ["dnf", "install", "-y", "--", "p"], ["dnf", "install", "-y", "/q/p.rpm"]),
    ("pacman", ["pacman", "-S", "--noconfirm", "--needed", "--", "p"], ["pacman", "-U", "--noconfirm", "/q/p.rpm"]),
    ("zypper", ["zypper", "--non-interactive", "install", "--", "p"], ["zypper", "--non-interactive", "install", "/q/p.rpm"]),
])
def test_package_manager_commands(pm, repo, local):
    assert installer.package_manager_command(pm, package_name="p") == repo
    assert installer.package_manager_command(pm, local_file="/q/p.rpm") == local


def test_wrong_package_format_for_this_distro_is_refused(runner, linux):
    runner.available = {"dnf"}
    with pytest.raises(InstallError, match="cannot be installed with dnf"):
        installer.build_commands(linux_pkg(fmt="deb"), "/q/a.deb", "")


# ------------------------------------------------------------ privilege gate
def test_real_install_without_admin_rights_is_refused_before_anything_runs(runner, as_user, windows, tmp_path):
    with pytest.raises(ElevationError):
        installer.install(win_pkg(), tmp_path / "a.zip", dry_run=False, workdir=tmp_path)
    with pytest.raises(ElevationError):
        installer.install_fwupd_device("a" * 40, dry_run=False)
    assert runner.calls == []


# ---------------------------------------------------------------- real runs
@pytest.fixture
def staged(tmp_path):
    path = tmp_path / "pkg.zip"
    path.write_bytes(driver_zip())
    return path


def test_pnputil_install_verifies_catalog_then_installs(runner, as_admin, windows, staged, tmp_path):
    runner.on("powershell", windows_powershell())
    res = installer.install(win_pkg(), staged, dry_run=False, workdir=tmp_path)
    assert res.status == "installed" and res.ok
    assert runner.programs() == ["powershell", "pnputil"]              # catalog signature, then pnputil
    args = runner.ran("pnputil")[0]
    assert args[0] == "/add-driver" and args[1].endswith("x200.inf") and args[2] == "/install"


@pytest.mark.parametrize("rc,status,ok", [(3010, "reboot-required", True), (259, "no-op", True), (5, "failed", False)])
def test_pnputil_exit_codes(runner, as_admin, windows, staged, tmp_path, rc, status, ok):
    runner.on("powershell", windows_powershell())
    runner.on("pnputil", common.Result(rc, "Driver package added.\n", ""))
    res = installer.install(win_pkg(), staged, dry_run=False, workdir=tmp_path)
    assert (res.status, res.ok, res.rc) == (status, ok, rc)


def test_catalog_signed_by_someone_else_blocks_pnputil(runner, as_admin, windows, staged, tmp_path):
    from conftest import authenticode_json
    runner.on("powershell", windows_powershell(signer=authenticode_json(subject="CN=Evil, O=Evil Corp")))
    res = installer.install(win_pkg(), staged, dry_run=False, workdir=tmp_path)
    assert res.status == "failed" and "not the pinned publisher" in res.detail
    assert runner.ran("pnputil") == []


def test_missing_inf_and_cab_unpack_failure(runner, as_admin, windows, staged, tmp_path):
    runner.on("powershell", windows_powershell())
    res = installer.install(win_pkg(inf_path="other.inf"), staged, dry_run=False, workdir=tmp_path)
    assert res.status == "failed" and "not in the driver package" in res.detail and runner.ran("pnputil") == []
    cab = win_pkg()
    cab["id"], cab["artifact"]["format"] = "intel.wifi.cab", "cab"
    runner.on("expand", common.Result(1, "", "corrupt cabinet"))
    res = installer.install(cab, staged, dry_run=False, workdir=tmp_path)
    assert res.status == "failed" and "cabinet" in res.detail and runner.ran("pnputil") == []


def test_pnputil_package_is_refused_on_linux(runner, as_admin, linux, staged, tmp_path):
    res = installer.install(win_pkg(), staged, dry_run=False, workdir=tmp_path)
    assert res.status == "failed" and "only be installed on Windows" in res.detail and runner.calls == []


def test_linux_repo_install_runs_package_manager_noninteractively(runner, as_admin, linux):
    runner.available = {"apt-get", "dkms"}
    runner.on("dkms", common.Result(0, "nvidia/550.120, 6.8.0-45-generic, x86_64: installed\n"))
    res = installer.install(linux_pkg(package_name="nvidia-driver-550", reboot_required=True), None, dry_run=False)
    assert res.status == "reboot-required" and "DKMS: nvidia/550.120" in res.detail
    prog, args, env = runner.calls[0]
    assert (prog, args[-2:]) == ("apt-get", ["--", "nvidia-driver-550"]) and env["DEBIAN_FRONTEND"] == "noninteractive"


def test_linux_failures(runner, as_admin, linux):
    runner.available = set()
    res = installer.install(linux_pkg(package_name="p"), None, dry_run=False)
    assert res.status == "failed" and "no supported package manager" in res.detail
    runner.available = {"dnf"}
    runner.on("dnf", common.Result(1, "", "Error: Unable to find a match: p"))
    assert "Unable to find a match" in installer.install(linux_pkg(package_name="p"), None, dry_run=False).detail
    res = installer.install(linux_pkg("fwupd", "fwupd-cab"), "/q/fw.cab", dry_run=False)
    assert res.status == "failed" and "fwupdmgr is not available" in res.detail


def test_fwupd_install_and_nothing_to_do(runner, as_admin, linux):
    runner.available = {"fwupdmgr"}
    assert installer.install(linux_pkg("fwupd", "fwupd-cab"), "/q/fw.cab", dry_run=False).status == "installed"
    runner.on("fwupdmgr", common.Result(2, "", "No updates available"))
    assert installer.install_fwupd_device("b" * 40, dry_run=False).status == "no-op"
    with pytest.raises(InstallError, match="malformed"):
        installer.install_fwupd_device("--allow-older", dry_run=False)


# --------------------------------------------------------------- extraction
@pytest.mark.parametrize("member", ["../evil.inf", "/abs/evil.inf", "a/../../evil.inf", "C:\\Windows\\evil.inf",
                                    "..\\evil.inf"])
def test_zip_path_traversal_is_refused(tmp_path, member):
    archive = tmp_path / "bad.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr(member, b"x")
    with pytest.raises(InstallError, match="escapes"):
        installer.safe_extract_zip(archive, tmp_path / "out")
    assert not (tmp_path / "evil.inf").exists()


def test_zip_symlinks_are_refused_and_good_archives_extract(tmp_path):
    archive = tmp_path / "link.zip"
    info = zipfile.ZipInfo("link.inf")
    info.external_attr = 0o120777 << 16
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr(info, "/etc/passwd")
    with pytest.raises(InstallError, match="symbolic link"):
        installer.safe_extract_zip(archive, tmp_path / "out")
    good = tmp_path / "good.zip"
    good.write_bytes(driver_zip({"sub/extra.inf": b"x"}))
    names = sorted(p.name for p in installer.safe_extract_zip(good, tmp_path / "ok"))
    assert names == ["extra.inf", "x200.cat", "x200.inf", "x200.sys"]
