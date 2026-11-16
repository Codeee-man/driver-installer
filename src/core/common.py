"""Shared plumbing: platform facts, errors, audit log, subprocess runner.

Other modules read `common.OS_NAME` and call `common.run` at call time (never
`from common import run`), so tests can swap both and exercise the Windows code
paths on Linux.
"""
from __future__ import annotations

import base64
import dataclasses
import datetime as dt
import hashlib
import json
import ntpath
import os
import platform
import shutil
import subprocess
import sys
import threading
from pathlib import Path

APP = "SafeDriver"
VERSION = "1.0.0"
OS_NAME = "windows" if os.name == "nt" else "linux" if sys.platform.startswith("linux") else sys.platform
ARCH = {"amd64": "x86_64", "x86_64": "x86_64", "arm64": "aarch64", "aarch64": "aarch64",
        "i386": "x86", "i686": "x86", "x86": "x86"}.get(platform.machine().lower(), platform.machine().lower())
# Elevated code never resolves programs through the caller's PATH.
TRUSTED_PATH = "/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/sbin:/usr/local/bin"
_WIN_SYSTEM = {"powershell": r"WindowsPowerShell\v1.0\powershell.exe", "pnputil": "pnputil.exe",
               "expand": "expand.exe", "icacls": "icacls.exe"}


# Process exit codes shared by the CLI and the elevated helper.
EXIT_OK, EXIT_FAILED, EXIT_REFUSED, EXIT_NOT_CONFIRMED, EXIT_SNAPSHOT, EXIT_ELEVATION = 0, 1, 2, 3, 4, 5
EXIT_SECURITY, EXIT_BLOCKLIST = 6, 7
EXIT_USAGE = 64
RESULT_EXIT = {"ok": EXIT_OK, "nothing": EXIT_OK, "partial": EXIT_FAILED, "failed": EXIT_FAILED,
               "refused": EXIT_REFUSED, "snapshot_failed": EXIT_SNAPSHOT,
               "security_alert": EXIT_SECURITY, "blocklist_unavailable": EXIT_BLOCKLIST}


class VerificationError(Exception):
    """A manifest, download, hash or signature failed a check."""


class InstallError(Exception):
    """An install step could not be carried out."""


class ElevationError(Exception):
    """Administrator rights were required and are missing or were declined."""


# ------------------------------------------------------------------ paths
def state_dir() -> Path:
    """Per-user state (audit log, quarantine, plans)."""
    if OS_NAME == "windows":
        return Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")) / APP
    return Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state")) / "safedriver"


def system_state_dir() -> Path:
    """State owned by the elevated helper (results, rollback counter, its audit log)."""
    if OS_NAME == "windows":
        return Path(os.environ.get("ProgramData", r"C:\ProgramData")) / APP
    return Path("/var/lib/safedriver")


def _windows_system_dir() -> str:
    try:
        import ctypes
        buf = ctypes.create_unicode_buffer(260)
        if ctypes.windll.kernel32.GetSystemDirectoryW(buf, 260):
            return buf.value
    except (AttributeError, OSError):
        pass
    return ntpath.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")


def resolve_binary(name: str) -> str | None:
    """Absolute path of a system tool, looked up only in trusted locations."""
    if OS_NAME == "windows":
        rel = _WIN_SYSTEM.get(name.lower())
        if rel:
            path = ntpath.join(_windows_system_dir(), rel)
            return path if os.path.exists(path) else None
        return shutil.which(name)
    return shutil.which(name, path=TRUSTED_PATH)


def have(name: str) -> bool:
    return resolve_binary(name) is not None


# -------------------------------------------------------------- audit log
class AuditLog:
    """Append-only JSON Lines; every record carries the hash of the previous one."""
    GENESIS = "0" * 64

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._prev, self._seq = self.GENESIS, 0
        self.listeners: list = []
        if self.path.exists():
            last = None
            with self.path.open("rb") as fh:
                for line in fh:
                    if line.strip():
                        last = line
            if last:
                try:
                    rec = json.loads(last)
                    self._prev, self._seq = rec["hash"], rec["seq"] + 1
                except (ValueError, KeyError):
                    pass

    @staticmethod
    def _digest(rec: dict) -> str:
        body = {k: v for k, v in rec.items() if k != "hash"}
        return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    def write(self, event: str, **data) -> None:
        with self._lock:
            rec = {"seq": self._seq, "ts": dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds"),
                   "event": event, "data": data, "prev": self._prev}
            rec["hash"] = self._digest(rec)
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec, sort_keys=True, default=str) + "\n")
            self._prev, self._seq = rec["hash"], self._seq + 1
        for cb in list(self.listeners):
            cb(rec)

    @classmethod
    def verify_chain(cls, path: Path) -> tuple[bool, str]:
        prev, n = cls.GENESIS, 0
        with Path(path).open(encoding="utf-8") as fh:
            for n, line in enumerate(fh, 1):
                try:
                    rec = json.loads(line)
                except ValueError:
                    return False, f"line {n}: not valid JSON"
                if rec.get("prev") != prev or rec.get("hash") != cls._digest(rec):
                    return False, f"line {n}: chain broken (record edited, removed or reordered)"
                prev = rec["hash"]
        return True, f"{n} records, chain intact"


_audit: AuditLog | None = None


def init_audit(path: Path | None = None) -> AuditLog:
    global _audit
    _audit = AuditLog(path or state_dir() / "audit.jsonl")
    return _audit


def audit(event: str, **data) -> None:
    (_audit or init_audit()).write(event, **data)


def audit_log() -> AuditLog:
    return _audit or init_audit()


# ------------------------------------------------------------- subprocess
@dataclasses.dataclass
class Result:
    rc: int
    stdout: str = ""
    stderr: str = ""


def run(cmd: list[str], timeout: int = 600, env: dict | None = None, log_args: bool = True) -> Result | None:
    """Run a system tool without a shell. None means the tool is missing or did not start."""
    exe = cmd[0] if os.path.isabs(cmd[0]) else resolve_binary(cmd[0])
    if not exe:
        audit("exec.unavailable", program=cmd[0])
        return None
    full_env = {**os.environ, "LC_ALL": "C", **(env or {})}
    if OS_NAME != "windows":
        full_env["PATH"] = TRUSTED_PATH
    flags = 0x08000000 if OS_NAME == "windows" else 0  # CREATE_NO_WINDOW
    try:
        proc = subprocess.run([exe, *cmd[1:]], capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=timeout, env=full_env, creationflags=flags)
    except (OSError, subprocess.TimeoutExpired) as exc:
        audit("exec.error", program=cmd[0], error=str(exc))
        return None
    audit("exec", program=cmd[0], args=[a[:160] for a in cmd[1:]] if log_args else "<fixed script>",
          rc=proc.returncode)
    return Result(proc.returncode, proc.stdout, proc.stderr)


def powershell(script: str, env: dict | None = None, timeout: int = 600) -> Result | None:
    """Run a fixed Windows PowerShell script. Values go in through `env`, never by string building."""
    encoded = base64.b64encode(script.encode("utf-16-le")).decode()
    return run(["powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
               timeout=timeout, env=env, log_args=False)
