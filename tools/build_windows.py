#!/usr/bin/env python3
"""Build the Windows release: DriverInstaller-Windows-Portable.zip and DriverInstaller-Setup.exe.

    py tools\\build_windows.py [--version 1.2.3] [--out dist] [--setup auto|yes|no]

Runs PyInstaller on packaging/windows/driver-installer.spec against a staged copy of src/
(version stamped in). The portable folder holds exactly:

    DriverInstaller/
      DriverInstaller.exe     GUI (double-click), CLI (any arguments), elevated helper (--apply-plan)
      _internal/...           Python runtime, PySide6, the VT323 font, licenses/ (LICENSE, VT323-OFL.txt)
      BUILD-INFO.txt          version, commit, SHA-256 of DriverInstaller.exe, signature

Then Inno Setup (packaging/windows/DriverInstaller.iss) packs the same folder into
DriverInstaller-Setup.exe, which installs to C:\\Program Files\\Driver Installer with an
admin-only ACL and can put a `driver-installer` command on PATH. --setup auto (the default)
builds it when iscc.exe is found; yes requires it; no skips it.

Code signing: with WINDOWS_PFX_BASE64 and WINDOWS_PFX_PASSWORD set, DriverInstaller.exe is
Authenticode-signed (signtool, SHA-256, RFC 3161 timestamp) right after PyInstaller, before
it is hashed and zipped; Inno Setup signs Setup.exe and its uninstaller through the same
tools/codesign_windows.py while compiling, and the result is read back. Without the secrets
everything is unsigned. See docs/SIGNING.md.

Requires: Python 3.10+, `pip install pyinstaller PySide6 cryptography`, Inno Setup 6 for the
installer. The spec also runs on Linux (producing a Linux binary), which is how the layout is
checked without Windows.
"""
from __future__ import annotations

import argparse
import datetime as dt
import os
import platform
import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from build_common import (FONT, FONT_LICENSE, ROOT, BuildError, find_windows_tool, resolve_version, run,  # noqa: E402
                          sha256_file, stage_source, warn_if_unpinned)
import codesign_windows  # noqa: E402

SPEC = ROOT / "packaging" / "windows" / "driver-installer.spec"
ISS = ROOT / "packaging" / "windows" / "DriverInstaller.iss"
PROGRAM = "DriverInstaller"
ZIP_NAME = "DriverInstaller-Windows-Portable.zip"
SETUP_NAME = "DriverInstaller-Setup.exe"
# The portable folder contains these and nothing else.
PORTABLE_TOP_LEVEL = {"DriverInstaller.exe", "_internal", "BUILD-INFO.txt"}
LICENSES = ("LICENSE", FONT_LICENSE.name)       # under _internal/licenses/
SHIM = ('@echo off\r\n'
        'rem Driver Installer command line. DriverInstaller.exe is a windowed program; started\r\n'
        'rem from this script, cmd.exe waits for it and passes its exit code on.\r\n'
        '"%~dp0DriverInstaller.exe" %*\r\n'
        'exit /b %ERRORLEVEL%\r\n')


def numeric_version(version: str) -> tuple[int, int, int, int]:
    """Windows version resources need four integers: 1.2.3-rc1+gitabc -> (1, 2, 3, 0)."""
    parts = [int(p) for p in version.split("+")[0].split("-")[0].split(".")[:4] if p.isdigit()]
    return tuple((parts + [0, 0, 0, 0])[:4])


def version_resource(version: str, path: Path) -> Path:
    n = numeric_version(version)
    strings = {"CompanyName": "Driver Installer project", "FileDescription": "Driver Installer",
               "FileVersion": version, "InternalName": PROGRAM, "LegalCopyright": "MIT License",
               "OriginalFilename": f"{PROGRAM}.exe", "ProductName": "Driver Installer", "ProductVersion": version}
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
        _app = QGuiApplication.instance() or QGuiApplication([])     # QImage needs a running app
        target = work / "driver-installer.ico"
        if QImage(str(ROOT / "contrib" / "icons" / "driver-installer.png")).save(str(target), "ICO"):
            return target
    except Exception as exc:                         # the build works without an icon
        print(f"note: no icon ({exc})", file=sys.stderr)
    return None


def check_pe_metadata(exe: Path, version: str) -> None:
    """Windows only: windowed (GUI subsystem, so no console flash), the manifest asks for no
    elevation (asInvoker), and the version resource is set. Uses `pefile`."""
    try:
        import pefile
    except ImportError:
        print("note: pefile not installed; manifest and version resource not checked", file=sys.stderr)
        return
    pe = pefile.PE(str(exe))
    if pe.OPTIONAL_HEADER.Subsystem != pefile.SUBSYSTEM_TYPE["IMAGE_SUBSYSTEM_WINDOWS_GUI"]:
        raise BuildError(f"{exe.name}: not a windowed (GUI subsystem) program")
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


def exe_path(app_dir: Path) -> Path:
    return app_dir / (PROGRAM + (".exe" if platform.system() == "Windows" else ""))


def check_layout(app_dir: Path) -> None:
    """Nothing but the program, its runtime and BUILD-INFO.txt at the top of the portable folder."""
    names = {p.name for p in app_dir.iterdir()}
    if platform.system() != "Windows":
        names = {n + ".exe" if n == PROGRAM else n for n in names}
    extra = names - PORTABLE_TOP_LEVEL
    if extra:
        raise BuildError(f"unexpected files in the portable folder: {sorted(extra)}")


def verify(app_dir: Path, version: str) -> dict[str, str]:
    """The folder as it will ship. Returns {name: sha256} of the program."""
    exe = exe_path(app_dir)
    if not exe.is_file():
        raise BuildError(f"{exe.name} was not built")
    if platform.system() == "Windows":
        check_pe_metadata(exe, version)
    check_layout(app_dir)
    fonts = list(app_dir.rglob(FONT.name))
    if not fonts or sha256_file(fonts[0]) != sha256_file(FONT):
        raise BuildError(f"{FONT.name} is missing from the bundle or differs from the source")
    for name in LICENSES:
        if not (app_dir / "_internal" / "licenses" / name).is_file():
            raise BuildError(f"_internal/licenses/{name} is missing")
    # Captured output = redirected handles: what a script or the .cmd shim sees.
    out = subprocess.run([str(exe), "--version"], capture_output=True, text=True, timeout=120)
    if version not in out.stdout:
        raise BuildError(f"{exe.name} --version printed {out.stdout!r}{out.stderr!r}, expected {version}")
    helper = subprocess.run([str(exe), "--apply-plan"], capture_output=True, timeout=120)
    if helper.returncode != 64:
        raise BuildError(f"helper mode should refuse an incomplete command line with exit code 64, got {helper.returncode}")
    return {exe.name: sha256_file(exe)}


def sign(app_dir: Path) -> codesign_windows.SigningResult:
    """Sign DriverInstaller.exe when the signing secrets are set (Windows only: signtool)."""
    if platform.system() != "Windows":
        if codesign_windows.secrets() is not None:
            raise BuildError("code signing needs signtool.exe, which exists only on Windows")
        return codesign_windows.SigningResult(False, reason="not built on Windows")
    return codesign_windows.sign_executables([exe_path(app_dir)])


def find_iscc(env=None) -> Path | None:
    found = find_windows_tool("iscc", "ISCC", ("Inno Setup 6/ISCC.exe",), env)
    return found[0] if found else None


def iscc_command(iscc: Path, version: str, app_dir: Path, shim: Path, out: Path, icon: Path | None,
                 signing: bool) -> list[str]:
    n = ".".join(map(str, numeric_version(version)))
    cmd = [str(iscc), "/Qp", f"/DAppVersion={version}", f"/DNumericVersion={n}",
           f"/DSourceDir={app_dir}", f"/DShimFile={shim}", f"/DOutputDir={out}"]
    if icon:
        cmd.append(f"/DIconFile={icon}")
    if signing:
        cmd += ["/DSign", codesign_windows.iscc_signtool()]
    return cmd + [str(ISS)]


def build_setup(app_dir: Path, version: str, out: Path, work: Path, icon: Path | None, mode: str) -> Path | None:
    """Compile DriverInstaller-Setup.exe from the finished (signed) portable folder."""
    if mode == "no":
        return None
    iscc = find_iscc() if platform.system() == "Windows" else None
    if iscc is None:
        if mode == "yes":
            raise BuildError("Inno Setup's iscc.exe was not found (install Inno Setup 6 or set ISCC)")
        codesign_windows.notice(f"iscc.exe not found; {SETUP_NAME} not built (portable zip only).")
        return None
    shim = work / "setup" / "driver-installer.cmd"
    shim.parent.mkdir(parents=True, exist_ok=True)
    shim.write_bytes(SHIM.encode("ascii"))
    cert = codesign_windows.configured()
    target = out / SETUP_NAME
    target.unlink(missing_ok=True)
    run(iscc_command(iscc, version, app_dir, shim, out, icon, cert is not None))
    if not target.is_file():
        raise BuildError(f"iscc finished but {target} is missing")
    require_administrator(target)                     # changes bytes: any signature from iscc is now stale
    if cert is not None:
        codesign_windows.sign_executables([target])   # signs the patched file (replacing iscc's signature)
    print(f"built {target} ({target.stat().st_size // (1 << 20)} MiB, sha256 {sha256_file(target)})")
    return target


# Inno Setup's loader always ships with requestedExecutionLevel "asInvoker" and restarts itself
# elevated after it has started. On first launch, antivirus interception (e.g. AVG CyberCapture)
# or the download mark can break that restart, and Setup then reports that the UAC prompt was
# declined although none appeared. No .iss directive changes this, but Inno pads the attribute
# with spaces so it can be switched in place: the file keeps its size and layout, and Windows
# shows the UAC prompt itself, before Setup runs at all.
AS_INVOKER = b'level="asInvoker"            uiAccess="false"'
REQUIRE_ADMIN = b'level="requireAdministrator" uiAccess="false"'
assert len(AS_INVOKER) == len(REQUIRE_ADMIN)


def require_administrator(setup: Path) -> None:
    """Switch DriverInstaller-Setup.exe's manifest to requireAdministrator, in place, before it
    is signed. Raises BuildError unless exactly one manifest entry was found and switched."""
    data = setup.read_bytes()
    found = data.count(AS_INVOKER)
    if found != 1 and data.count(REQUIRE_ADMIN) == 1:
        return                                          # already done
    if found != 1:
        raise BuildError(f"{setup.name}: expected one asInvoker manifest entry to switch, found {found}; "
                         "has Inno Setup changed its manifest?")
    patched = data.replace(AS_INVOKER, REQUIRE_ADMIN)
    assert len(patched) == len(data)
    setup.write_bytes(patched)
    level = manifest_level(setup)                       # None: pefile missing, the byte check stands
    if level not in (None, "requireAdministrator"):
        raise BuildError(f"{setup.name}: manifest asks for {level!r} after patching")
    print(f"{setup.name}: manifest now requests requireAdministrator (UAC before Setup starts)")


def manifest_level(exe: Path) -> str | None:
    """requestedExecutionLevel from the PE manifest resource (needs pefile; None without it)."""
    try:
        import pefile
    except ImportError:
        return None
    pe = pefile.PE(str(exe), fast_load=True)
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])
    for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE") else []:
        if entry.id == pefile.RESOURCE_TYPE["RT_MANIFEST"]:
            for sub in entry.directory.entries:
                for lang in sub.directory.entries:
                    text = pe.get_data(lang.data.struct.OffsetToData, lang.data.struct.Size).decode("utf-8", "replace")
                    m = re.search(r'requestedExecutionLevel\s+level="([^"]+)"', text)
                    if m:
                        return m.group(1)
    return None


def write_zip(app_dir: Path, target: Path) -> Path:
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for path in sorted(app_dir.rglob("*")):
            if path.is_file():
                zf.write(path, Path(PROGRAM) / path.relative_to(app_dir))
    print(f"built {target} ({target.stat().st_size // (1 << 20)} MiB, sha256 {sha256_file(target)})")
    return target


def build(version: str, out: Path, work: Path, setup: str = "auto") -> list[Path]:
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)
    src = stage_source(work / "src", version)
    shutil.copy2(ROOT / "LICENSE", src / "LICENSE")             # bundled under _internal/licenses
    warn_if_unpinned(src)
    env = {**os.environ, "DI_STAGED_SRC": str(src), "DI_VERSION_FILE": str(version_resource(version, work / "version.txt"))}
    icon = icon_file(work)
    if icon:
        env["DI_ICON"] = str(icon)
    dist = work / "dist"
    run([sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--distpath", dist,
         "--workpath", work / "pyinstaller", str(SPEC)], env=env)
    app_dir = dist / PROGRAM
    signing = sign(app_dir)
    hashes = verify(app_dir, version)              # hashes of the files as shipped, i.e. after signing
    commit = os.environ.get("GITHUB_SHA") or subprocess.run(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    (app_dir / "BUILD-INFO.txt").write_text(
        f"Driver Installer {version}\ncommit {commit or 'unknown'}\nbuilt {dt.datetime.now(dt.timezone.utc):%Y-%m-%d %H:%M UTC} "
        f"on {platform.system()} {platform.machine()}, Python {platform.python_version()}\n\nSHA-256\n"
        + "".join(f"  {h}  {n}\n" for n, h in hashes.items()) + "\n" + signing.build_info(), encoding="utf-8")
    out = out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    built = [write_zip(app_dir, out / ZIP_NAME)]
    installer = build_setup(app_dir, version, out, work, icon, setup)
    return built + ([installer] if installer else [])


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--version", help="release version (default: from the v* tag, else <version>+git<sha>)")
    ap.add_argument("--out", type=Path, default=ROOT / "dist")
    ap.add_argument("--work", type=Path, default=ROOT / "build" / "windows")
    ap.add_argument("--setup", choices=("auto", "yes", "no"), default="auto",
                    help=f"build {SETUP_NAME} with Inno Setup (default: when iscc.exe is found)")
    args = ap.parse_args(argv)
    try:
        build(resolve_version(args.version), args.out, args.work, args.setup)
    except (BuildError, subprocess.CalledProcessError, OSError) as exc:
        print(f"build_windows: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
