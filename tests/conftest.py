"""Shared fixtures. No test touches the real system: commands go to FakeRunner,
state goes to tmp_path, and elevation is always simulated."""
from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path

import pytest

from core import common, elevation, engine, installer, manifest, trust, verifier
from core.security import loldrivers

FIXTURES = Path(__file__).parent / "fixtures"
REAL_LOLDRIVERS_FETCH = loldrivers.fetch          # the autouse fixture below replaces it with a canned feed
RESTORE_CREATED = json.dumps({"Before": 41, "After": 42, "Warning": "", "Error": None})
RESTORE_DISABLED = json.dumps({"Before": None, "After": None, "Warning": "",
                               "Error": "System Restore is disabled. Contact your system administrator."})


class FakeRunner:
    """Stands in for common.run / common.have. Records every command instead of executing it."""

    def __init__(self):
        self.calls: list[tuple[str, list[str], dict]] = []
        self.available: set[str] = {"powershell", "pnputil", "expand", "icacls"}
        self.responses: dict[str, object] = {}

    def on(self, program: str, response) -> None:
        """response: common.Result, or callable(cmd, env) -> common.Result | None"""
        self.responses[program] = response

    def run(self, cmd, timeout=600, env=None, log_args=True):
        prog = cmd[0]
        if prog not in self.available:
            return None
        self.calls.append((prog, list(cmd[1:]), dict(env or {})))
        resp = self.responses.get(prog, common.Result(0))
        return resp(cmd, env or {}) if callable(resp) else resp

    def have(self, name):
        return name in self.available

    def programs(self) -> list[str]:
        return [c[0] for c in self.calls]

    def ran(self, program: str) -> list[list[str]]:
        return [c[1] for c in self.calls if c[0] == program]


@pytest.fixture(autouse=True)
def isolated_state(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "localappdata"))
    monkeypatch.setattr(common, "system_state_dir", lambda: tmp_path / "system")
    monkeypatch.setenv("ProgramFiles", str(tmp_path / "ProgramFiles"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))     # UI preferences never touch the real home
    monkeypatch.setenv("APPDATA", str(tmp_path / "appdata"))
    monkeypatch.setattr(installer, "HELPER_LINUX", str(tmp_path / "no-helper-installed"))
    monkeypatch.setattr(installer, "HELPER_LINUX_PACKAGED", str(tmp_path / "no-packaged-helper"))
    monkeypatch.setattr(engine, "AUTO_DISCOVER", False)          # no test talks to the internet by accident
    monkeypatch.setattr(loldrivers, "fetch", lambda *a, **k: canned_blocklist())
    common.init_audit(tmp_path / "audit.jsonl")
    yield


@pytest.fixture
def runner(monkeypatch):
    fake = FakeRunner()
    monkeypatch.setattr(common, "run", fake.run)
    monkeypatch.setattr(common, "have", fake.have)
    return fake


@pytest.fixture
def as_user(monkeypatch):
    monkeypatch.setattr(elevation, "is_admin", lambda: False)


@pytest.fixture
def as_admin(monkeypatch):
    monkeypatch.setattr(elevation, "is_admin", lambda: True)


@pytest.fixture
def windows(monkeypatch):
    monkeypatch.setattr(common, "OS_NAME", "windows")
    monkeypatch.setattr(common, "ARCH", "x86_64")


@pytest.fixture
def linux(monkeypatch):
    monkeypatch.setattr(common, "OS_NAME", "linux")
    monkeypatch.setattr(common, "ARCH", "x86_64")
    monkeypatch.setattr(manifest, "_distro_ids", lambda: {"ubuntu", "debian"})


@pytest.fixture
def loopback(monkeypatch):
    """Let the pipeline fetch from the local test server (URL rules are tested separately)."""
    monkeypatch.setattr(manifest, "_url_ok", lambda url, loopback_ok: True)
    monkeypatch.setattr(verifier, "_check_url", lambda url, allow: None)


@pytest.fixture
def pin(monkeypatch):
    """Sign a manifest with a fresh key and pin that key, as a release build would."""
    import demo

    def _pin(document: dict):
        raw, sig, keys = demo.sign(document)
        monkeypatch.setattr(trust, "PINNED_MANIFEST_KEYS", keys)
        return raw, sig
    return _pin


def driver_zip(extra: dict[str, bytes] | None = None) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("x200.inf", "[Version]\nSignature=\"$WINDOWS NT$\"\nClass=Net\nCatalogFile=x200.cat\n")
        zf.writestr("x200.cat", b"catalog-bytes")
        zf.writestr("x200.sys", b"MZ-driver-bytes")
        for name, data in (extra or {}).items():
            zf.writestr(name, data)
    return buf.getvalue()


def authenticode_json(subject="CN=Intel Corporation, O=Intel Corporation, L=Santa Clara, S=California, C=US",
                      status="Valid", thumbprint="0123456789ABCDEF0123456789ABCDEF01234567") -> str:
    return json.dumps({"Status": status, "StatusMessage": "", "Subject": subject, "Issuer": "CN=Test CA",
                       "Thumbprint": thumbprint, "SignatureType": "Authenticode", "TimeStamped": True})


def windows_powershell(restore=RESTORE_CREATED, signer=None):
    """PowerShell stand-in: answers the Authenticode and restore-point scripts by their env inputs."""
    def respond(cmd, env):
        if "SD_FILE" in env:
            return common.Result(0, signer or authenticode_json())
        if "SD_DESC" in env:
            return common.Result(0, restore)
        return common.Result(0, "[]")
    return respond


KNOWN_BAD_SYS = b"MZ" + b"known vulnerable driver image" * 64      # stands in for a LOLDrivers sample


def loldrivers_feed(extra_samples: list[dict] | None = None, filler: int = 600) -> bytes:
    """A feed shaped like https://www.loldrivers.io/api/drivers.json, with KNOWN_BAD_SYS listed."""
    import hashlib
    drivers = [{"Id": f"00000000-0000-0000-0000-{i:012d}", "Category": "vulnerable driver", "Tags": [f"filler{i}.sys"],
                "Verified": "TRUE", "KnownVulnerableSamples": [{
                    "Filename": f"filler{i}.sys", "SHA256": hashlib.sha256(b"filler%d" % i).hexdigest(),
                    "SHA1": hashlib.sha1(b"filler%d" % i).hexdigest(), "MD5": hashlib.md5(b"filler%d" % i).hexdigest(),
                    "Authentihash": {"SHA256": "0" * 64}}]} for i in range(filler)]
    drivers.append({"Id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "Category": "malicious", "Tags": ["evil.sys"],
                    "KnownVulnerableSamples": [{"Filename": "evil.sys",
                                                "SHA256": hashlib.sha256(KNOWN_BAD_SYS).hexdigest().upper()},
                                               *(extra_samples or [])]})
    drivers.append({"Id": "unverified-entry", "Category": "vulnerable driver", "Tags": ["WinIo64A.sys"],
                    "Verified": "FALSE", "KnownVulnerableSamples": [{"Filename": "WinIo64A.sys", "OriginalFilename": "",
                                                                     "Authentihash": {"SHA1": "0c74d09d" * 5}}]})
    return json.dumps(drivers).encode()


def canned_blocklist():
    return loldrivers.parse(loldrivers_feed())
