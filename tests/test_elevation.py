"""Elevation plumbing: admin check, method selection, declined prompts."""
import ctypes
import subprocess
import sys

import pytest

from core import common, elevation
from core.common import ElevationError


@pytest.mark.skipif(ctypes.sizeof(ctypes.c_void_p) != 8, reason="x64 layout")
def test_shellexecuteinfo_layout_matches_the_win64_abi():
    assert ctypes.sizeof(elevation.SHELLEXECUTEINFOW) == 112
    assert elevation.SHELLEXECUTEINFOW.hProcess.offset == 104
    assert elevation.SHELLEXECUTEINFOW.lpVerb.offset == 16


def test_is_admin_is_false_when_the_windows_api_is_unavailable(windows):
    if not hasattr(ctypes, "windll"):
        assert elevation.is_admin() is False


def test_no_elevation_mechanism_raises_instead_of_running_unelevated(runner, linux, monkeypatch):
    runner.available = set()
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: pytest.fail("must not run anything"))
    with pytest.raises(ElevationError, match="administrator rights are required"):
        elevation.run_elevated(["/usr/bin/python3", "cli.py", "--apply-plan", "p"])


def test_pkexec_is_used_and_a_declined_prompt_is_reported(runner, linux, monkeypatch):
    runner.available = {"pkexec"}
    monkeypatch.setenv("DISPLAY", ":0")
    monkeypatch.setattr(common, "resolve_binary", lambda name: f"/usr/bin/{name}")
    seen = []

    def fake_run(argv, **kw):
        seen.append(argv)
        return subprocess.CompletedProcess(argv, fake_run.rc)
    monkeypatch.setattr(subprocess, "run", fake_run)
    fake_run.rc = 0
    assert elevation.run_elevated(["/usr/bin/python3", "-I", "cli.py", "--apply-plan", "p"]) == 0
    assert seen[0] == ["/usr/bin/pkexec", "/usr/bin/python3", "-I", "cli.py", "--apply-plan", "p"]
    fake_run.rc = 126                                   # user dismissed the polkit dialog
    with pytest.raises(ElevationError, match="declined"):
        elevation.run_elevated(["/usr/bin/python3", "cli.py"])


def test_sudo_fallback_needs_a_terminal(runner, linux, monkeypatch):
    runner.available = {"sudo"}
    monkeypatch.delenv("DISPLAY", raising=False)
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False, raising=False)
    assert elevation.method() is None
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True, raising=False)
    assert elevation.method() == "sudo"


def test_windows_uses_uac(windows):
    assert elevation.method() == "uac"
