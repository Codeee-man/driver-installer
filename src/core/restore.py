"""Pre-install rollback point: Windows System Restore, Timeshift or snapper.

`create()` is called by the elevated helper after every package has passed
verification and before the first install command. Callers decide what a
non-ok result means (see engine.execute_plan); this module only reports.
"""
from __future__ import annotations

import dataclasses
import json

from . import common

DESCRIPTION = "Pre-Driver-Installer Update"

# Checkpoint-Computer is silent in two cases that are not success: System
# Restore disabled (it throws) and a restore point already made in the last
# 24 hours (it only warns). Comparing sequence numbers tells them apart.
_WINDOWS_PS = r"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
function Top { try { (Get-ComputerRestorePoint | Measure-Object -Property SequenceNumber -Maximum).Maximum } catch { $null } }
$before = Top
$err = $null
try {
  Checkpoint-Computer -Description $env:SD_DESC -RestorePointType DEVICE_DRIVER_INSTALL -WarningVariable warn -WarningAction SilentlyContinue
} catch { $err = $_.Exception.Message }
$after = Top
[pscustomobject]@{ Before = $before; After = $after; Warning = (@($warn) -join ' '); Error = $err } | ConvertTo-Json -Compress
"""


@dataclasses.dataclass
class RestoreResult:
    status: str            # created | existing | unavailable | failed | dry-run
    tool: str = ""
    detail: str = ""
    ident: str = ""

    @property
    def ok(self) -> bool:
        return self.status in ("created", "existing")


def detect() -> str | None:
    """Which mechanism would be used on this machine."""
    if common.OS_NAME == "windows":
        return "system-restore"
    for tool in ("timeshift", "snapper"):
        if common.have(tool):
            return tool
    return None


def commands(tool: str, description: str = DESCRIPTION) -> list[str]:
    if tool == "system-restore":
        return ["powershell", "Checkpoint-Computer", "-Description", f'"{description}"',
                "-RestorePointType", "DEVICE_DRIVER_INSTALL"]
    if tool == "timeshift":
        return ["timeshift", "--create", "--comments", description, "--tags", "O", "--scripted"]
    if tool == "snapper":
        return ["snapper", "-c", "root", "create", "--type", "single", "--cleanup-algorithm", "number",
                "--print-number", "--description", description]
    raise ValueError(tool)


def parse_windows_result(text: str) -> RestoreResult:
    try:
        d = json.loads(text)
    except (ValueError, TypeError):
        return RestoreResult("failed", "system-restore", "could not read the result of Checkpoint-Computer")
    before, after = d.get("Before") or 0, d.get("After") or 0
    if d.get("Error"):
        hint = " Turn on System Protection for the system drive to enable restore points." \
            if "disabled" in d["Error"].lower() or "turned off" in d["Error"].lower() else ""
        return RestoreResult("failed", "system-restore", d["Error"] + hint)
    if after > before:
        return RestoreResult("created", "system-restore", "restore point created", str(after))
    if d.get("Warning") and after:
        return RestoreResult("existing", "system-restore",
                             "Windows already made a restore point in the last 24 hours and reused it", str(after))
    return RestoreResult("failed", "system-restore", d.get("Warning") or "no restore point was created")


def _create_windows(description: str) -> RestoreResult:
    res = common.powershell(_WINDOWS_PS, env={"SD_DESC": description}, timeout=900)
    if res is None or res.rc != 0:
        return RestoreResult("failed", "system-restore", (res.stderr.strip()[:300] if res else "PowerShell unavailable"))
    return parse_windows_result(res.stdout)


def _create_linux(description: str) -> RestoreResult:
    failures = []
    for tool in ("timeshift", "snapper"):
        if not common.have(tool):
            continue
        res = common.run(commands(tool, description), timeout=3600)
        if res and res.rc == 0:
            ident = res.stdout.strip().splitlines()[-1] if tool == "snapper" and res.stdout.strip() else ""
            return RestoreResult("created", tool, f"{tool} snapshot created", ident)
        failures.append(f"{tool}: " + ((res.stderr or res.stdout).strip().splitlines() or ["failed"])[-1][:200]
                        if res else f"{tool}: did not start")
    if failures:
        return RestoreResult("failed", "", "; ".join(failures))
    return RestoreResult("unavailable", "", "neither Timeshift nor snapper is installed; no snapshot was taken")


def create(description: str = DESCRIPTION, dry_run: bool = False) -> RestoreResult:
    tool = detect()
    if dry_run:
        return RestoreResult("dry-run", tool or "", " ".join(commands(tool, description)) if tool else
                             "no snapshot tool found (Timeshift/snapper)")
    result = _create_windows(description) if common.OS_NAME == "windows" else _create_linux(description)
    event = "restore.created" if result.ok else "restore.warning" if result.status == "unavailable" else "restore.failed"
    common.audit(event, **dataclasses.asdict(result))
    return result
