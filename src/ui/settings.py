"""Remembered UI preferences (currently just the theme). Pure Python, no Qt.

Per user:   ~/.config/driver-installer/ui.json   (%APPDATA%\\driver-installer\\ui.json on Windows)
System:     /etc/driver-installer/ui.json        (read-only default an administrator may set)

Precedence when the window opens: --theme on the command line, then the user file, then the
system file, then the built-in default. --theme is for that launch only; the in-app toggle
is what saves a choice.
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from core import common
from . import theme as _theme

SYSTEM_FILE = Path("/etc/driver-installer/ui.json")


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


def load() -> dict:
    """System defaults overlaid with the user's own file. Unknown or invalid values are dropped."""
    merged = {**_read(SYSTEM_FILE), **_read(user_file())}
    if merged.get("theme") not in _theme.NAMES:
        merged.pop("theme", None)
    return merged


def save(**values) -> bool:
    """Merge values into the user file, atomically. Returns False (and changes nothing) on error."""
    path = user_file()
    data = {**_read(path), **values}
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


def startup_theme(cli_choice: str | None = None) -> str:
    if cli_choice in _theme.NAMES:
        return cli_choice
    return load().get("theme", _theme.DEFAULT)
