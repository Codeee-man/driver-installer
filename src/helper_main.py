#!/usr/bin/env python3
"""Elevated helper entry point.

This is the only program SafeDriver ever runs with administrator rights. It
accepts exactly one form of command line:

    driver-installer-helper --apply-plan <plan.json>
    DriverInstaller.exe --apply-plan <plan.json>       (Windows: the same program as the GUI/CLI)

No other option exists here on purpose (no --log, no --manifest), so whoever
is allowed to elevate it cannot point it at arbitrary files. Everything inside
the plan is treated as untrusted; see core/engine.execute_plan.

Deployed by tools/install_helper.sh (/usr/local/bin/driver-installer-helper), the .deb
(/usr/libexec/driver-installer/), DriverInstaller-Setup.exe
(%ProgramFiles%\\Driver Installer\\DriverInstaller.exe) and, for a source checkout,
tools/install_helper.ps1 (%ProgramFiles%\\driver-installer\\helper.exe).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))  # needed under `python -I`

from core import common, elevation, engine  # noqa: E402


def _say(text: str, stream=None) -> None:
    stream = stream or sys.stdout
    if stream is not None:              # a windowless .exe has no stdout/stderr
        print(text, file=stream)


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 2 or argv[0] != "--apply-plan":
        _say("usage: driver-installer-helper --apply-plan <plan.json>", sys.stderr)
        return common.EXIT_USAGE
    if not elevation.is_admin():
        _say("the helper must run with administrator rights", sys.stderr)
        return common.EXIT_ELEVATION
    common.init_audit(common.system_state_dir() / "audit.jsonl")
    result = engine.execute_plan(Path(argv[1]))
    _say(json.dumps(result))
    return common.RESULT_EXIT.get(result["status"], common.EXIT_FAILED)


if __name__ == "__main__":
    sys.exit(main())
