"""Build scripts (tools/build_linux.py, tools/build_windows.py) and how the program finds its
elevated helper when packaged. The .deb is built for real (pure Python, a few seconds); the
AppImage and PyInstaller builds need network and minutes, so they run in the build workflow."""
import importlib.util
import json
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from core import common, elevation, installer
from core.common import ElevationError

ROOT = Path(__file__).resolve().parents[1]


def load_tool(name):
    sys.path.insert(0, str(ROOT / "tools"))
    spec = importlib.util.spec_from_file_location(name, ROOT / "tools" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


build_common = load_tool("build_common")
build_linux = load_tool("build_linux")
build_windows = load_tool("build_windows")


# ------------------------------------------------------------- versions
@pytest.mark.parametrize("env,explicit,expected", [
    ({"GITHUB_REF_TYPE": "tag", "GITHUB_REF_NAME": "v1.4.0"}, None, "1.4.0"),
    ({"GITHUB_REF_TYPE": "branch", "GITHUB_REF_NAME": "main"}, "2.0.0-rc1", "2.0.0-rc1"),
    ({"RELEASE_VERSION": "v3.1"}, None, "3.1"),
])
def test_resolve_version(monkeypatch, env, explicit, expected):
    for key in ("GITHUB_REF_TYPE", "GITHUB_REF_NAME", "RELEASE_VERSION"):
        monkeypatch.delenv(key, raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    assert build_common.resolve_version(explicit) == expected


def test_untagged_builds_get_a_git_suffix_and_bad_versions_are_refused(monkeypatch):
    for key in ("GITHUB_REF_TYPE", "GITHUB_REF_NAME", "RELEASE_VERSION"):
        monkeypatch.delenv(key, raising=False)
    assert build_common.resolve_version().startswith(build_common.source_version() + "+git")
    with pytest.raises(build_common.BuildError):
        build_common.resolve_version("1.0; rm -rf /")


def test_windows_version_resource_numbers():
    assert build_windows.numeric_version("1.2.3") == (1, 2, 3, 0)
    assert build_windows.numeric_version("0.2.0+gitabc123") == (0, 2, 0, 0)
    assert build_windows.numeric_version("2.0.0-rc1") == (2, 0, 0, 0)


def test_staged_source_is_clean_and_stamped(tmp_path):
    staged = build_common.stage_source(tmp_path / "src", "9.8.7")
    assert 'VERSION = "9.8.7"' in (staged / "core" / "common.py").read_text()
    assert (staged / "ui" / "assets" / "fonts" / "VT323-Regular.ttf").is_file()
    assert not list(staged.rglob("__pycache__"))
    assert 'VERSION = "9.8.7"' not in (ROOT / "src" / "core" / "common.py").read_text()   # source untouched


# ------------------------------------------------------------------ .deb
@pytest.fixture(scope="module")
def deb(tmp_path_factory):
    out = tmp_path_factory.mktemp("dist")
    return build_linux.build_deb("1.2.3", out, tmp_path_factory.mktemp("work"))


def test_deb_layout_permissions_and_assets(deb):
    contents = build_linux.deb_members(deb)
    expect = {
        "usr/bin/driver-installer": 0o755,
        "usr/libexec/driver-installer/driver-installer-helper": 0o755,
        "usr/lib/driver-installer/ui/assets/fonts/VT323-Regular.ttf": 0o644,
        "usr/share/polkit-1/actions/org.safedriver.driver-installer.policy": 0o644,
        "usr/lib/systemd/user/driver-installer.service": 0o644,
        "usr/lib/systemd/user/driver-installer.timer": 0o644,
        "usr/share/applications/driver-installer.desktop": 0o644,
        "usr/share/doc/driver-installer/copyright": 0o644,
    }
    for name, mode in expect.items():
        assert stat.S_IMODE(contents[name]) == mode, name
    assert not any(name.startswith("usr/local") for name in contents)        # Debian policy
    assert not any("__pycache__" in name or name.startswith("usr/lib/driver-installer/tests") for name in contents)
    assert deb.name == "driver-installer_1.2.3_all.deb"


def _member(deb, wanted):
    import io
    import tarfile
    raw = deb.read_bytes()
    pos = 8
    while pos < len(raw):
        header = raw[pos:pos + 60]
        name, size = header[:16].decode().strip(), int(header[48:58])
        data = raw[pos + 60:pos + 60 + size]
        pos += 60 + size + (size % 2)
        if name.startswith(wanted[0]):
            with tarfile.open(fileobj=io.BytesIO(data)) as tar:
                return tar.extractfile("./" + wanted[1]).read().decode()


def test_deb_points_polkit_and_systemd_at_the_packaged_paths(deb):
    policy = _member(deb, ("data.tar", "usr/share/polkit-1/actions/org.safedriver.driver-installer.policy"))
    assert f">{build_linux.HELPER}</annotate>" in policy and "/usr/local/" not in policy
    service = _member(deb, ("data.tar", "usr/lib/systemd/user/driver-installer.service"))
    assert "ExecStart=/usr/bin/driver-installer check --notify --quiet" in service and "/usr/local/" not in service
    helper = _member(deb, ("data.tar", "usr/libexec/driver-installer/driver-installer-helper"))
    assert "exec /usr/bin/python3 -I /usr/lib/driver-installer/helper_main.py" in helper
    control = _member(deb, ("control.tar", "control"))
    assert "Version: 1.2.3\n" in control and "Architecture: all" in control
    assert "Depends: python3 (>= 3.10), python3-cryptography, gpgv\n" in control
    assert "pkexec | policykit-1" in control.split("Recommends:")[1].splitlines()[0]
    copyright_text = _member(deb, ("data.tar", "usr/share/doc/driver-installer/copyright"))
    assert "License: OFL-1.1" in copyright_text and "License: MIT" in copyright_text


@pytest.mark.skipif(not __import__("shutil").which("dpkg-deb"), reason="dpkg-deb not installed")
def test_dpkg_accepts_the_package(deb):
    info = subprocess.run(["dpkg-deb", "--field", str(deb), "Package", "Version"], capture_output=True, text=True)
    assert info.returncode == 0 and "Package: driver-installer" in info.stdout and "Version: 1.2.3" in info.stdout


def test_deb_build_is_reproducible(tmp_path, monkeypatch):
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000000")
    a = build_linux.build_deb("1.0.0", tmp_path / "a", tmp_path / "wa")
    b = build_linux.build_deb("1.0.0", tmp_path / "b", tmp_path / "wb")
    assert a.read_bytes() == b.read_bytes()


# ----------------------------------------------------- Windows spec, pins
def test_windows_spec_builds_one_windowed_program_with_font_and_licenses():
    spec = (ROOT / "packaging" / "windows" / "driver-installer.spec").read_text()
    assert '(os.path.join(SRC, fonts, "VT323-Regular.ttf"), fonts)' in spec
    assert '(os.path.join(SRC, "LICENSE"), "licenses")' in spec and '"VT323-OFL.txt"), "licenses")' in spec
    assert 'windows_main.py' in spec and spec.count("EXE(") == 1 and "console=False" in spec
    assert '"helper_main"' in spec                              # helper mode needs it bundled
    assert build_windows.ZIP_NAME == "DriverInstaller-Windows-Portable.zip"
    assert build_windows.SETUP_NAME == "DriverInstaller-Setup.exe"
    assert not hasattr(build_windows, "EXTRA_FILES")            # nothing loose next to the program


def test_appimage_inputs_are_pinned():
    assert len(build_linux.PBS_SHA256) == 64 and len(build_linux.APPIMAGETOOL_SHA256) == 64
    assert all("==" in r for r in build_linux.APPIMAGE_REQUIREMENTS)
    assert "--apply-plan" in build_linux.APPRUN and '-I "$APP/helper_main.py"' in build_linux.APPRUN


def test_download_refuses_a_wrong_checksum(tmp_path, monkeypatch):
    import io
    monkeypatch.setattr(build_common.urllib.request, "urlopen", lambda url, timeout: io.BytesIO(b"tampered"))
    with pytest.raises(build_common.BuildError, match="checksum mismatch"):
        build_common.download("https://example.invalid/x", tmp_path / "x", "0" * 64)
    assert not (tmp_path / "x").exists() and not (tmp_path / "x.part").exists()


# ------------------------------------------------ helper lookup when packaged
def test_packaged_deb_helper_is_found(tmp_path, linux, monkeypatch):
    helper = tmp_path / "libexec" / "driver-installer-helper"
    helper.parent.mkdir()
    helper.write_text("#!/bin/sh\n")
    monkeypatch.setattr(elevation, "HELPER_LINUX_PACKAGED", str(helper))
    monkeypatch.setattr(elevation, "_admin_only", lambda path: True)
    assert elevation.helper_command("/p.json") == [str(helper), "--apply-plan", "/p.json"]


def test_frozen_build_uses_its_sibling_helper(tmp_path, linux, monkeypatch, caplog):
    exe = tmp_path / "driver-installer"
    exe.write_text("")
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(exe))
    with pytest.raises(ElevationError, match="driver-installer-helper is missing"):
        elevation.helper_command("/p.json")
    (tmp_path / "driver-installer-helper").write_text("")
    assert elevation.helper_command("/p.json") == [str(tmp_path / "driver-installer-helper"), "--apply-plan", "/p.json"]
    assert "running un-installed" in caplog.text


def test_frozen_windows_build_elevates_itself_unless_installed(tmp_path, windows, monkeypatch):
    """DriverInstaller.exe is GUI, CLI and helper: a portable copy elevates itself (with a
    warning); once DriverInstaller-Setup.exe has installed it, the Program Files copy is used."""
    monkeypatch.setattr(elevation.ntpath, "join", __import__("os").path.join)
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    portable = tmp_path / "unzipped" / "DriverInstaller.exe"
    monkeypatch.setattr(sys, "executable", str(portable))
    portable.parent.mkdir()
    portable.write_text("")
    assert elevation.helper_command("p.json") == [str(portable.resolve()), "--apply-plan", "p.json"]
    installed = tmp_path / "ProgramFiles" / "Driver Installer" / "DriverInstaller.exe"
    installed.parent.mkdir(parents=True)
    installed.write_text("")
    assert elevation.helper_command("p.json") == [str(installed), "--apply-plan", "p.json"]


def test_appimage_elevates_itself_without_needing_fuse(tmp_path, linux, monkeypatch):
    image = tmp_path / "driver-installer.AppImage"
    image.write_text("")
    monkeypatch.setenv("APPIMAGE", str(image))
    assert elevation.helper_command("/p.json") == [str(image), "--appimage-extract-and-run", "--apply-plan", "/p.json"]


def test_gui_without_pyside_explains_what_to_install(monkeypatch, capsys):
    import builtins

    import cli
    real_import = builtins.__import__

    def no_pyside(name, *a, **k):
        if name == "PySide6":
            raise ImportError(name)
        return real_import(name, *a, **k)
    monkeypatch.setattr(builtins, "__import__", no_pyside)
    assert cli.main(["gui"]) == common.EXIT_FAILED
    assert "python3-pyside6.qtwidgets" in capsys.readouterr().err


def test_repository_layout_and_doc_links_are_current():
    import re as _re
    assert not (ROOT / "poc").exists() and not (ROOT / "TESTING_WINDOWS.md").exists()
    assert (ROOT / "docs" / "TESTING_WINDOWS.md").is_file()
    for doc in [ROOT / "README.md", *sorted((ROOT / "docs").glob("*.md"))]:
        text = doc.read_text(encoding="utf-8")
        assert "poc/" not in text, doc.name
        for target in _re.findall(r"\]\(([^)#\s]+)\)", text):
            if "://" not in target:
                assert (doc.parent / target).exists(), f"{doc.name}: broken link {target}"
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for path in ("packaging/windows/", "docs/TESTING_WINDOWS.md", "tools/codesign_windows.py",
                 "tools/diagnose_windows.ps1", "tools/build_windows.py"):
        name = path.rstrip("/").split("/")[-1]
        assert name in readme and (ROOT / path).exists(), path
    count = int(_re.search(r"# (\d+) tests", readme).group(1))
    assert count >= 357
    # The README's layout tree lists exactly what is there: every tool and doc, nothing removed.
    tree = readme[readme.index("Layout:"):]
    tree = tree[:tree.index("```", tree.index("```") + 3)]
    tools_block = tree[tree.index("\ntools/"):tree.index("\nschema/")]
    listed_tools = set(_re.findall(r"[\w.]+\.(?:py|sh|ps1)", tools_block)) | {"install_helper.ps1"}
    actual_tools = {f.name for f in (ROOT / "tools").iterdir() if f.is_file() and f.suffix in (".py", ".sh", ".ps1")}
    assert listed_tools == actual_tools, (listed_tools ^ actual_tools)
    docs_line = next(line for line in tree.splitlines() if line.startswith("docs/"))
    assert set(_re.findall(r"\w+\.md", docs_line)) == {f.name for f in (ROOT / "docs").glob("*.md")}
    for gone in ("docs/PHASE2.md", "tools/builder.py", "src/gui.py"):
        assert not (ROOT / gone).exists(), gone
        assert Path(gone).name not in tree, gone
    for doc in [ROOT / "README.md", *sorted((ROOT / "docs").glob("*.md"))]:
        assert "PHASE2" not in doc.read_text(encoding="utf-8"), doc.name
