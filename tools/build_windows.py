#!/usr/bin/env python3
"""Build the Windows release: dist/driver-installer-windows.zip.

    py tools\\build_windows.py [--version 1.2.3] [--out dist]

Runs PyInstaller on packaging/windows/driver-installer.spec against a staged copy of src/
(version stamped in), then lays out:

    driver-installer/
      driver-installer.exe          CLI (console)
      driver-installer-gui.exe      GUI (no console window)
      driver-installer-helper.exe   elevated helper, no Qt
      _internal/...                 Python runtime, PySide6, ui/assets/fonts/VT323-Regular.ttf
      install_helper.ps1            copies this folder to Program Files with an admin-only ACL
      README.md, LICENSE, SIGNING.md, TESTING_WINDOWS.md, VT323-OFL.txt, manifest.schema.json,
      example.manifest.json, BUILD-INFO.txt (version, commit, SHA-256 of each .exe)

Requires: Python 3.10+, `pip install pyinstaller PySide6 cryptography`. The spec also runs on
Linux (producing Linux binaries), which is how the layout is checked without Windows.

Code signing: with WINDOWS_PFX_BASE64 and WINDOWS_PFX_PASSWORD set, the three .exe files are
Authenticode-signed with signtool (SHA-256, RFC 3161 timestamp) right after PyInstaller, before
they are hashed and zipped. Without them the build is unsigned. See tools/codesign_windows.py
and docs/SIGNING.md.
"""
from __future__ import annotations

import argparse
import datetime as dt
import os
import platform
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from build_common import (FONT, FONT_LICENSE, ROOT, BuildError, resolve_version, run, sha256_file,  # noqa: E402
                          stage_source, warn_if_unpinned)
import codesign_windows  # noqa: E402

SPEC = ROOT / "packaging" / "windows" / "driver-installer.spec"
ZIP_NAME = "driver-installer-windows.zip"
PROGRAMS = ("driver-installer", "driver-installer-gui", "driver-installer-helper")
EXTRA_FILES = {
    "install_helper.ps1": ROOT / "tools" / "install_helper.ps1",
    "diagnose_windows.ps1": ROOT / "tools" / "diagnose_windows.ps1",
    "README.md": ROOT / "README.md",
    "LICENSE": ROOT / "LICENSE",
    "SIGNING.md": ROOT / "docs" / "SIGNING.md",
    "TESTING_WINDOWS.md": ROOT / "TESTING_WINDOWS.md",
    "VT323-OFL.txt": FONT_LICENSE,
    "manifest.schema.json": ROOT / "schema" / "manifest.schema.json",
    "example.manifest.json": ROOT / "schema" / "example.manifest.json",
}


def numeric_version(version: str) -> tuple[int, int, int, int]:
    """Windows version resources need four integers: 1.2.3-rc1+gitabc -> (1, 2, 3, 0)."""
    parts = [int(p) for p in version.split("+")[0].split("-")[0].split(".")[:4] if p.isdigit()]
    return tuple((parts + [0, 0, 0, 0])[:4])


def version_resource(version: str, path: Path) -> Path:
    n = numeric_version(version)
    strings = {"CompanyName": "Driver Installer project", "FileDescription": "Driver Installer",
               "FileVersion": version, "InternalName": "driver-installer", "LegalCopyright": "MIT License",
               "OriginalFilename": "driver-installer.exe", "ProductName": "Driver Installer", "ProductVersion": version}
    entries = ",\n            ".join(f"StringStruct({k!r}, {v!r})" for k, v in strings.items())
    path.write_text(f"""# UTF-8
VSVersionInfo(
  ffi=FixedFileInfo(filevers={n}, prodvers={n}, mask=0x3f, flags=0x0, OS=0x40004, fileType=0x1,
                    subtype=0x0, date=(0, 0)),
  kids=[
    StringFileInfo([StringTable('040904B0', [
            {entries}])]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)
""", encoding="utf-8")
    return path


def icon_file(work: Path) -> Path | None:
    """Convert the PNG icon to .ico with Qt (already a build dependency). Optional."""
    try:
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        from PySide6.QtGui import QGuiApplication, QImage
        app = QGuiApplication.instance() or QGuiApplication([])
        target = work / "driver-installer.ico"
        if QImage(str(ROOT / "contrib" / "icons" / "driver-installer.png")).save(str(target), "ICO"):
            return target
    except Exception as exc:                         # the build works without an icon
        print(f"note: no icon ({exc})", file=sys.stderr)
    return None


def check_pe_metadata(exe: Path, version: str) -> None:
    """Windows only: the manifest asks for no elevation (asInvoker) and the version resource is set.
    Uses `pefile` when installed (the build workflow installs it)."""
    try:
        import pefile
    except ImportError:
        print("note: pefile not installed; manifest and version resource not checked", file=sys.stderr)
        return
    pe = pefile.PE(str(exe))
    manifests = []
    resources = pe.DIRECTORY_ENTRY_RESOURCE.entries if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE") else []
    for entry in resources:
        if entry.id == pefile.RESOURCE_TYPE["RT_MANIFEST"]:
            for sub in entry.directory.entries:
                for lang in sub.directory.entries:
                    manifests.append(pe.get_data(lang.data.struct.OffsetToData, lang.data.struct.Size).decode("utf-8", "replace"))
    if not any('level="asInvoker"' in m for m in manifests):
        raise BuildError(f"{exe.name}: manifest does not request asInvoker")
    strings = {}
    for info in getattr(pe, "FileInfo", []) or []:
        for item in info:
            for table in getattr(item, "StringTable", []):
                strings.update({k.decode(): v.decode() for k, v in table.entries.items()})
    if strings.get("ProductVersion") != version or strings.get("ProductName") != "Driver Installer":
        raise BuildError(f"{exe.name}: version resource is {strings!r}")


def verify(app_dir: Path, version: str) -> dict[str, str]:
    suffix = ".exe" if platform.system() == "Windows" else ""
    hashes = {}
    for name in PROGRAMS:
        exe = app_dir / (name + suffix)
        if not exe.is_file():
            raise BuildError(f"{exe.name} was not built")
        hashes[exe.name] = sha256_file(exe)
        if platform.system() == "Windows":
            check_pe_metadata(exe, version)
    fonts = list(app_dir.rglob(FONT.name))
    if not fonts or sha256_file(fonts[0]) != sha256_file(FONT):
        raise BuildError(f"{FONT.name} is missing from the bundle or differs from the source")
    for name in EXTRA_FILES:
        if not (app_dir / name).is_file():
            raise BuildError(f"{name} is missing from the distribution folder")
    cli = app_dir / ("driver-installer" + suffix)
    out = subprocess.run([str(cli), "--version"], capture_output=True, text=True, timeout=120)
    if version not in out.stdout:
        raise BuildError(f"driver-installer --version printed {out.stdout!r}{out.stderr!r}, expected {version}")
    helper = subprocess.run([str(app_dir / ("driver-installer-helper" + suffix)), "--bogus"], timeout=120)
    if helper.returncode != 64:
        raise BuildError(f"the helper should refuse unknown arguments with exit code 64, got {helper.returncode}")
    return hashes


def sign(app_dir: Path) -> codesign_windows.SigningResult:
    """Sign the three programs when the signing secrets are set (Windows only: signtool)."""
    if platform.system() != "Windows":
        if codesign_windows.secrets() is not None:
            raise BuildError("code signing needs signtool.exe, which exists only on Windows")
        return codesign_windows.SigningResult(False, reason="not built on Windows")
    return codesign_windows.sign_executables([app_dir / f"{name}.exe" for name in PROGRAMS])


def build(version: str, out: Path, work: Path) -> Path:
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)
    src = stage_source(work / "src", version)
    warn_if_unpinned(src)
    env = {**os.environ, "DI_STAGED_SRC": str(src), "DI_VERSION_FILE": str(version_resource(version, work / "version.txt"))}
    icon = icon_file(work)
    if icon:
        env["DI_ICON"] = str(icon)
    dist = work / "dist"
    run([sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--distpath", dist,
         "--workpath", work / "pyinstaller", str(SPEC)], env=env)
    app_dir = dist / "driver-installer"
    for name, source in EXTRA_FILES.items():
        if source.is_file():
            shutil.copy2(source, app_dir / name)
    signing = sign(app_dir)
    hashes = verify(app_dir, version)              # hashes of the files as shipped, i.e. after signing
    commit = os.environ.get("GITHUB_SHA") or subprocess.run(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    (app_dir / "BUILD-INFO.txt").write_text(
        f"Driver Installer {version}\ncommit {commit or 'unknown'}\nbuilt {dt.datetime.now(dt.timezone.utc):%Y-%m-%d %H:%M UTC} "
        f"on {platform.system()} {platform.machine()}, Python {platform.python_version()}\n\nSHA-256\n"
        + "".join(f"  {h}  {n}\n" for n, h in hashes.items()) + "\n" + signing.build_info(), encoding="utf-8")
    out.mkdir(parents=True, exist_ok=True)
    target = out / ZIP_NAME
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for path in sorted(app_dir.rglob("*")):
            if path.is_file():
                zf.write(path, Path("driver-installer") / path.relative_to(app_dir))
    print(f"built {target} ({target.stat().st_size // (1 << 20)} MiB, sha256 {sha256_file(target)})")
    return target


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--version", help="release version (default: from the v* tag, else <version>+git<sha>)")
    ap.add_argument("--out", type=Path, default=ROOT / "dist")
    ap.add_argument("--work", type=Path, default=ROOT / "build" / "windows")
    args = ap.parse_args(argv)
    try:
        build(resolve_version(args.version), args.out, args.work)
    except (BuildError, subprocess.CalledProcessError, OSError) as exc:
        print(f"build_windows: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
