"""Is there a newer Driver Installer release? One small HTTPS request to GitHub's public API.

    GET https://api.github.com/repos/Codeee-man/driver-installer/releases/latest

Only the release's tag_name is read and compared with the running version. Nothing about the
computer is sent (the User-Agent is the program name and version, which GitHub requires). Any
problem (offline, a proxy, rate limiting, a malformed answer) means "no update known": the
check never raises and never blocks; it is off when the user turns it off in Settings.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request

from . import common
from .model import parse_version

REPO = "Codeee-man/driver-installer"
LATEST_API = f"https://api.github.com/repos/{REPO}/releases/latest"
RELEASES_PAGE = f"https://github.com/{REPO}/releases/latest"
TIMEOUT = 3.0
MAX_BYTES = 256 * 1024
OPENER = urllib.request.urlopen                 # replaced in the tests: no test talks to GitHub


def latest_tag(opener=None, timeout: float = TIMEOUT) -> str | None:
    """tag_name of the latest published release, or None on any failure."""
    request = urllib.request.Request(LATEST_API, headers={
        "Accept": "application/vnd.github+json", "User-Agent": f"{common.APP}/{common.VERSION}"})
    try:
        with (opener or OPENER)(request, timeout=timeout) as response:
            data = json.loads(response.read(MAX_BYTES).decode("utf-8"))
    except (OSError, ValueError, urllib.error.URLError) as exc:      # offline, 403/429 rate limit, bad JSON
        common.audit("update_check.unavailable", error=f"{type(exc).__name__}: {exc}"[:200])
        return None
    tag = data.get("tag_name") if isinstance(data, dict) else None
    return tag if isinstance(tag, str) and tag.strip() else None


def is_newer(tag: str | None, running: str | None = None) -> bool:
    """True when release `tag` (v1.2.0) is newer than the running version (1.1.5, 1.1.5+gitabc)."""
    released = parse_version(tag)
    return bool(released) and released > parse_version(running or common.VERSION)


def update_available(opener=None, running: str | None = None, timeout: float = TIMEOUT) -> bool:
    running = running or common.VERSION
    tag = latest_tag(opener, timeout)
    newer = is_newer(tag, running)
    common.audit("update_check.done", latest=tag, running=running, newer=newer)
    return newer
