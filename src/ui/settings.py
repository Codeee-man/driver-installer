"""Remembered UI preferences: accent colour, font, and the startup update check. No Qt.

Per user:   ~/.config/driver-installer/ui.json   (%APPDATA%\\driver-installer\\ui.json on Windows)
System:     /etc/driver-installer/ui.json        (read-only defaults an administrator may set)

    {"accent": "green", "font": "vt323", "check_updates": true}

The user's file wins over the system file, which wins over the built-in defaults. Unknown keys
and invalid values are ignored (an old "theme" entry from versions with a Clean theme too).
The Settings dialog saves every change at once.
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from core import common
from . import theme as _theme

SYSTEM_FILE = Path("/etc/driver-installer/ui.json")
DEFAULTS = {"accent": _theme.DEFAULT_ACCENT, "font": _theme.DEFAULT_FONT, "check_updates": True}


def user_file() -> Path:
    if common.OS_NAME == "windows":
        base = Path(os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming")
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    return base / "driver-installer" / "ui.json"


def _read(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _valid(key: str, value) -> bool:
    if key == "accent":
        return value in _theme.ACCENTS
    if key == "font":
        return value in _theme.FONTS
    if key == "check_updates":
        return isinstance(value, bool)
    return False


def load() -> dict:
    """The effective preferences: built-in defaults, overlaid with the system file, then the
    user's own file. Always has every key of DEFAULTS, each with a valid value."""
    merged = dict(DEFAULTS)
    for source in (_read(SYSTEM_FILE), _read(user_file())):
        merged.update({k: v for k, v in source.items() if _valid(k, v)})
    return merged


def save(**values) -> bool:
    """Merge valid values into the user file, atomically. Returns False (and changes nothing)
    on error or when a value is invalid."""
    if not all(_valid(k, v) for k, v in values.items()):
        return False
    path = user_file()
    data = {k: v for k, v in _read(path).items() if _valid(k, v)}
    data.update(values)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".ui-", suffix=".json")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=1)
        os.replace(tmp, path)
    except OSError as exc:
        common.audit("ui.settings.save_failed", path=str(path), error=str(exc))
        return False
    return True
