"""UI preferences file (accent, font, update check). No Qt needed for the settings themselves."""
import json

import pytest

import cli
from ui import settings, theme


def test_user_file_location(linux):
    assert settings.user_file().parts[-3:] == ("config", "driver-installer", "ui.json")


def test_windows_user_file_is_under_appdata(windows, tmp_path):
    assert settings.user_file() == tmp_path / "appdata" / "driver-installer" / "ui.json"


def test_defaults_are_matrix_green_vt323_and_update_check_on(linux):
    assert settings.load() == {"accent": "green", "font": "vt323", "check_updates": True}
    assert not settings.user_file().exists()                    # loading never writes


def test_save_merges_and_load_validates(linux):
    assert settings.save(accent="orange")
    assert settings.save(font="mono", check_updates=False)
    assert json.loads(settings.user_file().read_text()) == {"accent": "orange", "font": "mono", "check_updates": False}
    assert settings.load() == {"accent": "orange", "font": "mono", "check_updates": False}
    # invalid values are refused on save and ignored on load; unknown and legacy keys are dropped
    assert settings.save(accent="neon") is False and settings.save(font="comic") is False
    assert settings.save(check_updates="yes") is False
    settings.user_file().write_text(json.dumps({"theme": "clean", "accent": "neon", "font": "sans", "other": 1}))
    assert settings.load() == {"accent": "green", "font": "sans", "check_updates": True}
    assert settings.save(accent="cyan")
    assert json.loads(settings.user_file().read_text()) == {"font": "sans", "accent": "cyan"}
    settings.user_file().write_text("not json")
    assert settings.load() == settings.DEFAULTS


def test_user_file_wins_over_system_defaults(linux, tmp_path, monkeypatch):
    system = tmp_path / "etc-ui.json"
    system.write_text('{"accent": "silver", "check_updates": false}')
    monkeypatch.setattr(settings, "SYSTEM_FILE", system)
    assert settings.load() == {"accent": "silver", "font": "vt323", "check_updates": False}   # administrator default
    settings.save(accent="amber")
    assert settings.load()["accent"] == "amber" and settings.load()["check_updates"] is False


def test_unwritable_config_is_not_fatal(linux, tmp_path, monkeypatch):
    blocker = tmp_path / "config"
    blocker.write_text("a file where a directory should be")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(blocker))
    assert settings.save(accent="cyan") is False
    assert settings.load() == settings.DEFAULTS


def test_presets_are_the_five_accents_and_three_fonts():
    assert {k: v for k, (_, v) in theme.ACCENTS.items()} == {
        "green": "#00FF66", "orange": "#FF6B1A", "cyan": "#00E5FF", "amber": "#FFB000", "silver": "#E4E8EF"}
    assert [label for label, _ in theme.ACCENTS.values()] == ["Matrix Green", "Vivid Orange", "Cyan", "Amber", "Silver"]
    assert [f.label for f in theme.FONTS.values()] == ["VT323", "Mono", "Sans"]
    assert theme.FONTS["vt323"].fonts[0] == "VT323"
    assert theme.FONTS["mono"].fonts[:2] == ("Consolas", "JetBrains Mono") and theme.FONTS["mono"].fixed
    assert theme.FONTS["sans"].fonts[1] == "Segoe UI" and not theme.FONTS["sans"].fixed
    assert (theme.DEFAULT_ACCENT, theme.DEFAULT_FONT) == ("green", "vt323")


def test_gui_has_no_theme_flag(monkeypatch):
    import gui
    seen = []
    monkeypatch.setattr(gui, "run", lambda ctx, tmp, shot: seen.append(shot) or 0)
    assert cli.main(["gui"]) == 0 and seen == [None]
    with pytest.raises(SystemExit):
        cli.main(["gui", "--theme", "clean"])                  # one design now: there is no Clean theme
