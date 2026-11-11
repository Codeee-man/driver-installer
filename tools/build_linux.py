#!/usr/bin/env python3
"""Build Linux release artifacts: a Debian package and an AppImage.

    python tools/build_linux.py deb      [--version 1.2.3] [--out dist]
    python tools/build_linux.py appimage [--version 1.2.3] [--out dist]
    python tools/build_linux.py all

.deb  (Architecture: all; needs python3, python3-cryptography, gpgv; pkexec recommended, else sudo)
    /usr/bin/driver-installer                               CLI / GUI launcher (runs unprivileged)
    /usr/libexec/driver-installer/driver-installer-helper   elevated helper, root-owned
    /usr/lib/driver-installer/                              application code, incl. the VT323 font
    /usr/share/polkit-1/actions/org.safedriver.driver-installer.policy
    /usr/lib/systemd/user/driver-installer.{service,timer}  weekly check, not enabled by default
    /usr/share/applications/, /usr/share/icons/hicolor/, /usr/share/doc/driver-installer/
  The helper goes to /usr/libexec, not /usr/local/bin: Debian packages must not install files
  under /usr/local, which belongs to the local administrator. The program looks in both places.
  The package is written directly (ar + tar, root:root, fixed timestamps), so dpkg-deb is only
  used to check the result when it is available.

.AppImage (x86_64)
    A standalone Python (python-build-standalone, pinned by SHA-256) with PySide6-Essentials and
    cryptography, plus the application. Needs FUSE to run, or APPIMAGE_EXTRACT_AND_RUN=1.
    Installing drivers from the AppImage elevates the AppImage file itself (with a warning),
    unless the .deb or tools/install_helper.sh has installed the protected helper.
"""
from __future__ import annotations

import argparse
import gzip
import io
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from build_common import (DESCRIPTION, FONT, HOMEPAGE, MAINTAINER, NAME, ROOT, BuildError, download,  # noqa: E402
                          resolve_version, run, sha256_file, stage_source, warn_if_unpinned)

APP_DIR = "/usr/lib/driver-installer"
BIN = "/usr/bin/driver-installer"
HELPER = "/usr/libexec/driver-installer/driver-installer-helper"
POLICY = "/usr/share/polkit-1/actions/org.safedriver.driver-installer.policy"
UNITS = "/usr/lib/systemd/user"
DEPENDS = "python3 (>= 3.10), python3-cryptography, gpgv"
RECOMMENDS = "pkexec | policykit-1, python3-pyside6.qtwidgets, python3-dbus, fwupd, timeshift | snapper"
SUGGESTS = "ubuntu-drivers-common"

# AppImage inputs, pinned. Bump deliberately, together with the checksums.
PBS_TAG = "20251217"
PBS_FILE = f"cpython-3.12.12+{PBS_TAG}-x86_64-unknown-linux-gnu-install_only.tar.gz"
PBS_SHA256 = "e065aa467072547dfcc1ebc58d5302b02e89e40bfc972e179d2bfce204e03450"
APPIMAGETOOL_VERSION = "1.9.0"
APPIMAGETOOL_SHA256 = "46fdd785094c7f6e545b61afcfb0f3d98d8eab243f644b4b17698c01d06083d1"
APPIMAGE_REQUIREMENTS = ["PySide6-Essentials==6.12.0", "cryptography==50.0.2"]
CACHE = ROOT / "build" / "cache"

# Parts of Python and PySide6 the application never loads; removed to keep the AppImage small.
PRUNE_PYTHON = ["lib/python3.12/test", "lib/python3.12/idlelib", "lib/python3.12/tkinter",
                "lib/python3.12/turtledemo", "lib/python3.12/ensurepip", "include", "share"]
PRUNE_PYSIDE = ["Qt/qml", "Qt/translations", "Qt/plugins/qmltooling", "Qt/plugins/qmllint", "include",
                "typesystems", "glue", "scripts", "designer", "assistant", "linguist", "lrelease", "lupdate",
                "qmlformat", "qmllint", "qmlls", "qmlcachegen", "qmlimportscanner", "qmltyperegistrar", "qsb",
                "rcc", "uic", "balsam", "balsamui", "svgtoqml", "androiddeployqt", "Qt/libexec"]
PRUNE_QT_LIB_PREFIXES = ("libQt6Quick", "libQt6Qml", "libQt6Designer", "libQt6Help", "libQt6Pdf",
                         "libQt6ShaderTools", "libQt6UiTools", "libQt6Labs")


def epoch() -> int:
    if os.environ.get("SOURCE_DATE_EPOCH"):
        return int(os.environ["SOURCE_DATE_EPOCH"])
    try:
        out = subprocess.run(["git", "-C", str(ROOT), "log", "-1", "--format=%ct"], capture_output=True,
                             text=True, check=True).stdout.strip()
        return int(out)
    except (OSError, subprocess.CalledProcessError, ValueError):
        return int(time.time())


def launcher(target: str, isolated: bool) -> str:
    return ("#!/bin/sh\n# Installed by the driver-installer package.\n"
            f"exec /usr/bin/python3 {'-I ' if isolated else ''}{target} \"$@\"\n")


# ------------------------------------------------------------------ .deb
class Tree:
    """Files for the data archive: path -> (bytes, mode). Directories are derived."""

    def __init__(self):
        self.files: dict[str, tuple[bytes, int]] = {}

    def add(self, path: str, data: bytes | str, mode: int = 0o644) -> None:
        self.files[path.lstrip("/")] = (data.encode() if isinstance(data, str) else data, mode)

    def add_tree(self, source: Path, prefix: str) -> None:
        for path in sorted(source.rglob("*")):
            if path.is_file():
                self.add(f"{prefix}/{path.relative_to(source).as_posix()}", path.read_bytes())

    def dirs(self) -> list[str]:
        out = set()
        for path in self.files:
            parts = path.split("/")[:-1]
            out.update("/".join(parts[:i]) for i in range(1, len(parts) + 1))
        return sorted(out)

    def installed_kb(self) -> int:
        return sum((len(d) + 1023) // 1024 for d, _ in self.files.values()) + len(self.dirs())


def _tar(entries: list[tuple[str, bytes | None, int]], mtime: int, compression: str) -> bytes:
    """Deterministic tar: fixed owner, mode and mtime; gzip header without a timestamp."""
    buf = io.BytesIO()
    mode = "w:xz" if compression == "xz" else "w"
    with tarfile.open(fileobj=buf, mode=mode, format=tarfile.GNU_FORMAT) as tar:
        for name, data, mode in entries:
            info = tarfile.TarInfo("./" + name if name else ".")
            info.uid = info.gid = 0
            info.uname = info.gname = "root"
            info.mtime = mtime
            info.mode = mode
            if data is None:
                info.type = tarfile.DIRTYPE
                tar.addfile(info)
            else:
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
    return gzip.compress(buf.getvalue(), compresslevel=9, mtime=0) if compression == "gz" else buf.getvalue()


def _ar(members: list[tuple[str, bytes]], mtime: int) -> bytes:
    out = bytearray(b"!<arch>\n")
    for name, data in members:
        out += f"{name:<16}{mtime:<12}{0:<6}{0:<6}{100644:<8}{len(data):<10}`\n".encode()
        out += data
        if len(data) % 2:
            out += b"\n"
    return bytes(out)


def deb_tree(src: Path, version: str) -> Tree:
    tree = Tree()
    tree.add_tree(src, APP_DIR)
    tree.add(BIN, launcher(f"{APP_DIR}/cli.py", isolated=False), 0o755)
    tree.add(HELPER, launcher(f"{APP_DIR}/helper_main.py", isolated=True), 0o755)
    policy = (ROOT / "contrib/polkit/org.safedriver.driver-installer.policy").read_text()
    tree.add(POLICY, policy.replace("/usr/local/bin/driver-installer-helper", HELPER))
    for unit in ("driver-installer.service", "driver-installer.timer"):
        text = (ROOT / "contrib/systemd" / unit).read_text()
        text = text.replace("/usr/local/bin/driver-installer", BIN)
        text = text.replace("sudo tools/install_helper.sh --with-timer", "the driver-installer package")
        tree.add(f"{UNITS}/{unit}", text)
    tree.add("/usr/share/applications/driver-installer.desktop", (ROOT / "contrib/desktop/driver-installer.desktop").read_text())
    tree.add("/usr/share/icons/hicolor/scalable/apps/driver-installer.svg", (ROOT / "contrib/icons/driver-installer.svg").read_bytes())
    tree.add("/usr/share/icons/hicolor/256x256/apps/driver-installer.png", (ROOT / "contrib/icons/driver-installer.png").read_bytes())
    doc = "/usr/share/doc/driver-installer"
    tree.add(f"{doc}/copyright", copyright_file())
    tree.add(f"{doc}/README.md", (ROOT / "README.md").read_bytes())
    for extra in ("docs/SIGNING.md", "TESTING_WINDOWS.md", "schema/manifest.schema.json", "schema/example.manifest.json"):
        tree.add(f"{doc}/{Path(extra).name}", (ROOT / extra).read_bytes())
    changelog = (f"driver-installer ({version}) unstable; urgency=medium\n\n  * Release {version}.\n\n"
                 f" -- {MAINTAINER}  {time.strftime('%a, %d %b %Y %H:%M:%S +0000', time.gmtime(epoch()))}\n")
    tree.add(f"{doc}/changelog.gz", gzip.compress(changelog.encode(), mtime=0))
    return tree


def copyright_file() -> str:
    mit = (ROOT / "LICENSE").read_text() if (ROOT / "LICENSE").is_file() else "MIT"
    ofl = FONT.with_name("VT323-OFL.txt").read_text()
    indent = lambda text: "\n".join(f" {line}" if line.strip() else " ." for line in text.strip().splitlines())  # noqa: E731
    return ("Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/\n"
            f"Upstream-Name: driver-installer\nSource: {HOMEPAGE}\n\n"
            "Files: *\nLicense: MIT\n" + indent(mit) + "\n\n"
            "Files: usr/lib/driver-installer/ui/assets/fonts/VT323-Regular.ttf\n"
            "Copyright: 2011, The VT323 Project Authors\nLicense: OFL-1.1\n" + indent(ofl) + "\n")


def control_file(version: str, installed_kb: int) -> str:
    return (f"Package: {NAME}\nVersion: {version}\nArchitecture: all\nMaintainer: {MAINTAINER}\n"
            f"Installed-Size: {installed_kb}\nDepends: {DEPENDS}\nRecommends: {RECOMMENDS}\nSuggests: {SUGGESTS}\n"
            f"Section: admin\nPriority: optional\nHomepage: {HOMEPAGE}\n"
            f"Description: {DESCRIPTION}\n"
            " Scans hardware, finds driver and firmware updates (signed manifest, Microsoft\n"
            " Update Catalog, fwupd/LVFS, distribution driver tools), verifies every package\n"
            " (SHA-256, Ed25519, Authenticode/GPG, LOLDrivers blocklist) and installs it\n"
            " after a restore point. No ads, no telemetry, no background service.\n")


POSTINST = f"""#!/bin/sh
set -e
# Byte-compile once as root; the installed code is not writable by users.
if [ "$1" = configure ] && command -v python3 >/dev/null; then
    python3 -m compileall -q {APP_DIR} >/dev/null 2>&1 || true
fi
exit 0
"""
PRERM = f"""#!/bin/sh
set -e
if [ "$1" = remove ] || [ "$1" = upgrade ]; then
    find {APP_DIR} -type d -name __pycache__ -prune -exec rm -rf {{}} + 2>/dev/null || true
fi
exit 0
"""


def build_deb(version: str, out: Path, work: Path) -> Path:
    src = stage_source(work / "src", version)
    warn_if_unpinned(src)
    tree = deb_tree(src, version)
    mtime = epoch()
    data_entries = [(d, None, 0o755) for d in tree.dirs()]
    data_entries += [(p, data, mode) for p, (data, mode) in sorted(tree.files.items())]
    md5 = "".join(f"{__import__('hashlib').md5(d).hexdigest()}  {p}\n" for p, (d, _) in sorted(tree.files.items()))
    control_entries = [("", None, 0o755), ("control", control_file(version, tree.installed_kb()).encode(), 0o644),
                       ("md5sums", md5.encode(), 0o644), ("postinst", POSTINST.encode(), 0o755),
                       ("prerm", PRERM.encode(), 0o755)]
    package = _ar([("debian-binary", b"2.0\n"), ("control.tar.gz", _tar(control_entries, mtime, "gz")),
                   ("data.tar.xz", _tar([("", None, 0o755)] + data_entries, mtime, "xz"))], mtime)
    out.mkdir(parents=True, exist_ok=True)
    target = out / f"{NAME}_{version}_all.deb"
    target.write_bytes(package)
    verify_deb(target)
    print(f"built {target} ({target.stat().st_size // 1024} KiB, sha256 {sha256_file(target)})")
    return target


def deb_members(path: Path) -> dict[str, int]:
    """{path inside the package: mode}, read back from the archive we wrote."""
    raw = path.read_bytes()
    if not raw.startswith(b"!<arch>\n"):
        raise BuildError("not an ar archive")
    pos, members = 8, {}
    while pos < len(raw):
        header = raw[pos:pos + 60]
        name, size = header[:16].decode().strip(), int(header[48:58])
        members[name] = raw[pos + 60:pos + 60 + size]
        pos += 60 + size + (size % 2)
    with tarfile.open(fileobj=io.BytesIO(members["data.tar.xz"])) as tar:
        return {m.name.removeprefix("./"): m.mode for m in tar.getmembers()}


def verify_deb(path: Path) -> None:
    contents = deb_members(path)
    required = {
        BIN.lstrip("/"): 0o755, HELPER.lstrip("/"): 0o755, POLICY.lstrip("/"): 0o644,
        f"{APP_DIR}/ui/assets/fonts/VT323-Regular.ttf".lstrip("/"): 0o644,
        f"{UNITS}/driver-installer.timer".lstrip("/"): 0o644, f"{UNITS}/driver-installer.service".lstrip("/"): 0o644,
        f"{APP_DIR}/helper_main.py".lstrip("/"): 0o644,
    }
    for name, mode in required.items():
        if name not in contents:
            raise BuildError(f"{path.name} is missing {name}")
        if stat.S_IMODE(contents[name]) != mode:
            raise BuildError(f"{name} has mode {oct(contents[name])}, expected {oct(mode)}")
    if shutil.which("dpkg-deb"):
        subprocess.run(["dpkg-deb", "--info", str(path)], check=True, stdout=subprocess.DEVNULL)
        listing = subprocess.run(["dpkg-deb", "--contents", str(path)], check=True, capture_output=True, text=True).stdout
        if any(not line.startswith(("-rw", "drw", "-rwx")) or " root/root " not in line for line in listing.splitlines()):
            raise BuildError("dpkg-deb reports files not owned by root/root")


# -------------------------------------------------------------- AppImage
APPRUN = """#!/bin/sh
# Driver Installer AppImage entry point.
HERE="$(dirname "$(readlink -f "$0")")"
PY="$HERE/opt/python/bin/python3"
APP="$HERE/opt/driver-installer"
if [ "$1" = "--apply-plan" ]; then
    # Elevated helper (started through pkexec/sudo by the GUI or CLI). -I: ignore PYTHON* variables.
    exec "$PY" -I "$APP/helper_main.py" "$@"
fi
[ $# -eq 0 ] && set -- gui
exec "$PY" -I "$APP/cli.py" "$@"
"""


def _prune(base: Path, relative: list[str]) -> None:
    for rel in relative:
        target = base / rel
        if target.is_dir() and not target.is_symlink():
            shutil.rmtree(target)
        elif target.exists() or target.is_symlink():
            target.unlink()


def build_appimage(version: str, out: Path, work: Path) -> Path:
    if os.uname().machine != "x86_64":
        raise BuildError("the AppImage build is x86_64 only")
    if not shutil.which("desktop-file-validate"):
        raise BuildError("appimagetool needs desktop-file-validate: apt install desktop-file-utils")
    appdir = work / "AppDir"
    if appdir.exists():
        shutil.rmtree(appdir)
    (appdir / "opt").mkdir(parents=True)
    pbs = download(f"https://github.com/astral-sh/python-build-standalone/releases/download/{PBS_TAG}/"
                   f"{PBS_FILE.replace('+', '%2B')}", CACHE / PBS_FILE, PBS_SHA256)
    with tarfile.open(pbs) as tar:
        tar.extractall(appdir / "opt", filter="tar")                # creates opt/python
    python = appdir / "opt" / "python" / "bin" / "python3"
    run([python, "-m", "pip", "install", "--no-cache-dir", "--disable-pip-version-check", "--no-warn-script-location",
         *APPIMAGE_REQUIREMENTS], env={**os.environ, "PIP_REQUIRE_VIRTUALENV": "0"})
    run([python, "-m", "pip", "uninstall", "-y", "-q", "pip"])
    _prune(appdir / "opt" / "python", PRUNE_PYTHON)
    pyside = appdir / "opt" / "python" / "lib" / "python3.12" / "site-packages" / "PySide6"
    _prune(pyside, PRUNE_PYSIDE)
    for lib in (pyside / "Qt" / "lib").glob("libQt6*"):
        if lib.name.startswith(PRUNE_QT_LIB_PREFIXES):
            lib.unlink()

    stage_source(appdir / "opt" / "driver-installer", version)
    warn_if_unpinned(appdir / "opt" / "driver-installer")
    (appdir / "AppRun").write_text(APPRUN)
    (appdir / "AppRun").chmod(0o755)
    desktop = (ROOT / "contrib/desktop/driver-installer.desktop").read_text().replace("Exec=driver-installer gui",
                                                                                       "Exec=driver-installer")
    (appdir / "driver-installer.desktop").write_text(desktop + f"X-AppImage-Version={version}\n")
    shutil.copy2(ROOT / "contrib/icons/driver-installer.png", appdir / "driver-installer.png")
    (appdir / ".DirIcon").symlink_to("driver-installer.png")
    licences = appdir / "usr" / "share" / "doc" / "driver-installer"
    licences.mkdir(parents=True)
    (licences / "copyright").write_text(copyright_file())

    tool = download(f"https://github.com/AppImage/appimagetool/releases/download/{APPIMAGETOOL_VERSION}/"
                    "appimagetool-x86_64.AppImage", CACHE / f"appimagetool-{APPIMAGETOOL_VERSION}-x86_64.AppImage",
                    APPIMAGETOOL_SHA256)
    tool.chmod(0o755)
    out.mkdir(parents=True, exist_ok=True)
    target = out / f"{NAME}-{version}-x86_64.AppImage"
    run([tool, "--no-appstream", appdir, target],
        env={**os.environ, "ARCH": "x86_64", "APPIMAGE_EXTRACT_AND_RUN": "1", "VERSION": version})
    verify_appimage(target, version)
    print(f"built {target} ({target.stat().st_size // (1 << 20)} MiB, sha256 {sha256_file(target)})")
    return target


def verify_appimage(path: Path, version: str) -> None:
    env = {**os.environ, "APPIMAGE_EXTRACT_AND_RUN": "1", "QT_QPA_PLATFORM": "offscreen"}
    res = subprocess.run([str(path), "--version"], env=env, capture_output=True, text=True, timeout=180)
    if res.returncode != 0 or version not in res.stdout:
        raise BuildError(f"AppImage --version failed: {res.stdout} {res.stderr}")
    res = subprocess.run([str(path), "--apply-plan"], env=env, capture_output=True, text=True, timeout=180)
    if res.returncode != 64:                      # helper entry point answers with its usage message
        raise BuildError(f"AppImage helper entry point misbehaves: rc={res.returncode} {res.stderr}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("target", choices=("deb", "appimage", "all"))
    ap.add_argument("--version", help="package version (default: from the v* tag, else <version>+git<sha>)")
    ap.add_argument("--out", type=Path, default=ROOT / "dist")
    ap.add_argument("--work", type=Path, default=ROOT / "build" / "linux")
    args = ap.parse_args(argv)
    try:
        version = resolve_version(args.version)
        built = []
        if args.target in ("deb", "all"):
            built.append(build_deb(version, args.out, args.work / "deb"))
        if args.target in ("appimage", "all"):
            built.append(build_appimage(version, args.out, args.work / "appimage"))
    except (BuildError, subprocess.CalledProcessError, OSError) as exc:
        print(f"build_linux: {exc}", file=sys.stderr)
        return 1
    for path in built:
        print(path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
