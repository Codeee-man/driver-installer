"""Shared helpers for tools/build_windows.py and tools/build_linux.py.

Both builds work from a clean staged copy of src/ (no __pycache__, no tests) with the release
version written into core/common.py, so `driver-installer --version` matches the package.
"""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
FONT = SRC / "ui" / "assets" / "fonts" / "VT323-Regular.ttf"
FONT_LICENSE = SRC / "ui" / "assets" / "fonts" / "VT323-OFL.txt"
NAME = "driver-installer"
DESCRIPTION = "Driver and firmware updater without ads, telemetry or background services"
HOMEPAGE = "https://github.com/Codeee-man/driver-installer"
MAINTAINER = "Driver Installer maintainers <noreply@users.noreply.github.com>"


class BuildError(Exception):
    pass


def source_version() -> str:
    text = (SRC / "core" / "common.py").read_text(encoding="utf-8")
    return re.search(r'^VERSION = "([^"]+)"', text, re.M).group(1)


def resolve_version(explicit: str | None = None) -> str:
    """Release version: --version, else a v* tag in GITHUB_REF_NAME, else <source version>+git<sha>."""
    candidate = explicit or os.environ.get("RELEASE_VERSION") or ""
    if not candidate and os.environ.get("GITHUB_REF_TYPE") == "tag":
        candidate = os.environ.get("GITHUB_REF_NAME", "")
    candidate = candidate.lstrip("v")
    if candidate:
        if not re.fullmatch(r"[0-9][0-9A-Za-z.+~-]*", candidate):
            raise BuildError(f"not a usable version: {candidate!r}")
        return candidate
    try:
        sha = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "--short", "HEAD"], capture_output=True,
                             text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        sha = "local"
    return f"{source_version()}+git{sha}"


def stage_source(dest: Path, version: str) -> Path:
    """Copy src/ to dest (without caches) and stamp the version. Returns dest."""
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(SRC, dest, ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".pytest_cache"))
    common_py = dest / "core" / "common.py"
    text = common_py.read_text(encoding="utf-8")
    common_py.write_text(re.sub(r'^VERSION = "[^"]+"', f'VERSION = "{version}"', text, count=1, flags=re.M),
                         encoding="utf-8")
    for required in (dest / "ui" / "assets" / "fonts" / FONT.name, dest / "helper_main.py", dest / "cli.py"):
        if not required.is_file():
            raise BuildError(f"staged source is missing {required.relative_to(dest)}")
    return dest


def pinned_keys_count(src: Path) -> int:
    text = (src / "core" / "trust.py").read_text(encoding="utf-8")
    return len(re.findall(r'^\s+"[0-9a-f]{16}": "[0-9a-f]{64}",', text, re.M))


def warn_if_unpinned(src: Path) -> None:
    if pinned_keys_count(src) == 0:
        print("warning: no manifest signing key is pinned in core/trust.py. This build refuses every\n"
              "         manifest; online discovery still works. See docs/SIGNING.md.", file=sys.stderr)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download(url: str, dest: Path, sha256: str) -> Path:
    """Download once into a cache, and refuse it unless its SHA-256 matches the pinned value."""
    if dest.is_file() and sha256_file(dest) == sha256:
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")
    print(f"downloading {url}")
    with urllib.request.urlopen(url, timeout=120) as resp, open(tmp, "wb") as out:
        shutil.copyfileobj(resp, out, 1 << 20)
    actual = sha256_file(tmp)
    if actual != sha256:
        tmp.unlink()
        raise BuildError(f"checksum mismatch for {url}: got {actual}, expected {sha256}")
    tmp.replace(dest)
    return dest


def run(cmd: list[str], **kw) -> None:
    print("+ " + " ".join(str(c) for c in cmd), flush=True)
    subprocess.run([str(c) for c in cmd], check=True, **kw)
