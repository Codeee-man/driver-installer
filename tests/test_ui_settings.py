"""UI preferences file and the --theme flag. No Qt needed for the settings themselves."""
import json

import pytest

import cli
from ui import settings


def test_user_file_location(linux):
    assert str(settings.user_file()).endswith("config/driver-installer/ui.json")


def test_windows_user_file_is_under_appdata(windows, tmp_path):
    assert settings.user_file() == tmp_path / "appdata" / "driver-installer" / "ui.json"


def test_save_merges_and_load_validates(linux):
    assert settings.load() == {}
    assert settings.save(theme="clean")
    settings.user_file().write_text(json.dumps({"theme": "clean", "other": 1}))
    assert settings.save(theme="matrix")
    assert json.loads(settings.user_file().read_text()) == {"theme": "matrix", "other": 1}
    settings.user_file().write_text('{"theme": "neon"}')
    assert "theme" not in settings.load()
    settings.user_file().write_text("not json")
    assert settings.load() == {} and settings.startup_theme() == "matrix"


def test_precedence_cli_then_user_then_system(linux, tmp_path, monkeypatch):
    system = tmp_path / "etc-ui.json"
    system.write_text('{"theme": "clean"}')
    monkeypatch.setattr(settings, "SYSTEM_FILE", system)
    assert settings.startup_theme() == "clean"                  # administrator default
    settings.save(theme="matrix")
    assert settings.startup_theme() == "matrix"                 # the user's own choice wins
    assert settings.startup_theme("clean") == "clean"           # --theme wins for that launch
    assert settings.startup_theme("bogus") == "matrix"


def test_unwritable_config_is_not_fatal(linux, tmp_path, monkeypatch):
    blocker = tmp_path / "config"
    blocker.write_text("a file where a directory should be")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(blocker))
    assert settings.save(theme="clean") is False


def test_cli_theme_flag(monkeypatch):
    import gui
    seen = {}
    monkeypatch.setattr(gui, "run", lambda ctx, tmp, shot, theme=None: seen.setdefault("theme", theme) and 0)
    cli.main(["gui", "--theme", "clean"])
    assert seen["theme"] == "clean"
    seen.clear()
    cli.main(["gui"])
    assert seen["theme"] is None
    with pytest.raises(SystemExit):
        cli.main(["gui", "--theme", "neon"])
