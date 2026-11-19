"""src/windows_main.py: how the single DriverInstaller.exe decides between GUI, CLI and the
elevated helper, and how a windowed process gets a console for CLI output."""
import io
import os
import sys
from pathlib import Path

import pytest

import windows_main


@pytest.fixture
def calls(monkeypatch):
    seen = []
    import cli
    import helper_main
    monkeypatch.setattr(cli, "main", lambda argv: seen.append(("cli", argv)) or 0)
    monkeypatch.setattr(helper_main, "main", lambda argv: seen.append(("helper", argv)) or 0)
    monkeypatch.setattr(windows_main, "attach_console", lambda: seen.append(("attach",)))
    return seen


def test_no_arguments_opens_the_gui_without_a_console(calls):
    assert windows_main.main([]) == 0
    assert calls == [("cli", ["gui"])]


def test_arguments_run_the_cli_on_the_callers_console(calls):
    windows_main.main(["scan", "--json"])
    assert calls == [("attach",), ("cli", ["scan", "--json"])]


def test_apply_plan_runs_the_helper_and_nothing_else(calls):
    windows_main.main(["--apply-plan", "C:/p.json"])
    assert calls == [("helper", ["--apply-plan", "C:/p.json"])]


def test_helper_branch_does_not_import_qt():
    import subprocess
    code = ("import sys, windows_main; sys.argv=['x','--apply-plan']; "
            "rc = windows_main.main(['--apply-plan']); "
            "print(rc, any(m.startswith(('PySide6', 'ui', 'gui')) for m in sys.modules))")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                         env={**os.environ, "PYTHONPATH": str(Path(windows_main.__file__).parent)})
    assert out.stdout.split() == ["64", "False"], out.stderr


class FakeKernel32:
    def __init__(self, attach_ok=True, handles=None):
        self.attach_ok, self.handles, self.attached = attach_ok, handles or {}, False

    def GetStdHandle(self, std):
        return self.handles.get(std)

    def GetFileType(self, handle):
        return 1

    def AttachConsole(self, pid):
        assert pid == windows_main.ATTACH_PARENT_PROCESS
        self.attached = True
        return self.attach_ok


def fake_open(log):
    def opener(target, mode, **kw):
        log.append((target, mode))
        return io.StringIO()
    return opener


def test_redirected_streams_are_kept_and_no_console_is_attached(monkeypatch):
    for name in ("stdin", "stdout", "stderr"):
        monkeypatch.setattr(sys, name, open(__file__))      # real file descriptors, like a pipe or file
    k32 = FakeKernel32()
    assert windows_main.attach_console(kernel32=k32, opener=fake_open([])) == "inherited"
    assert not k32.attached


def test_missing_streams_attach_to_the_parent_console(monkeypatch):
    for name in ("stdin", "stdout", "stderr"):
        monkeypatch.setattr(sys, name, None)               # a windowed process started from a console
    opened = []
    assert windows_main.attach_console(kernel32=FakeKernel32(), opener=fake_open(opened)) == "attached"
    assert opened == [("CONIN$", "r"), ("CONOUT$", "w"), ("CONOUT$", "w")]


def test_without_any_console_output_is_discarded_not_crashing(monkeypatch):
    for name in ("stdin", "stdout", "stderr"):
        monkeypatch.setattr(sys, name, None)               # e.g. a shortcut with arguments
    opened = []
    assert windows_main.attach_console(kernel32=FakeKernel32(attach_ok=False), opener=fake_open(opened)) == "none"
    assert {t for t, _ in opened} == {os.devnull}
    assert sys.stdout is not None


def test_only_stdin_missing_adds_nothing_to_redirected_output(monkeypatch):
    out = io.StringIO()
    monkeypatch.setattr(sys, "stdin", None)                # e.g. a scheduled task: no stdin, output to a file
    monkeypatch.setattr(sys, "stdout", out)
    monkeypatch.setattr(windows_main, "_usable", lambda stream: stream is not None)
    opened = []
    assert windows_main.attach_console(kernel32=FakeKernel32(), opener=fake_open(opened)) == "attached"
    assert opened == [("CONIN$", "r")] and out.getvalue() == ""
