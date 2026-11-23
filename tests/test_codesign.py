"""tools/codesign_windows.py: when signing runs, what it runs, that the PFX never outlives the
call, and where build_windows.py signs (before hashing and zipping). signtool itself is faked;
the build workflow signs and verifies for real on Windows."""
import base64
import datetime as dt
import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "tools" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


import codesign_windows as cs  # noqa: E402
BuildError = sys.modules["build_common"].BuildError


def make_pfx(password=b"pw", eku=True, days=(-1, 365), self_signed=True):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import pkcs12
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Driver Installer test")])
    issuer = name if self_signed else x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Some CA")])
    now = dt.datetime.now(dt.timezone.utc)
    builder = (x509.CertificateBuilder().subject_name(name).issuer_name(issuer).public_key(key.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(now + dt.timedelta(days=days[0])).not_valid_after(now + dt.timedelta(days=days[1])))
    usage = ExtendedKeyUsageOID.CODE_SIGNING if eku else ExtendedKeyUsageOID.SERVER_AUTH
    builder = builder.add_extension(x509.ExtendedKeyUsage([usage]), critical=False)
    cert = builder.sign(key, hashes.SHA256())
    enc = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
    return pkcs12.serialize_key_and_certificates(b"test", key, cert, None, enc)


@pytest.fixture(scope="module")
def pfx_b64():
    return base64.b64encode(make_pfx()).decode()


class FakeSigntool:
    def __init__(self, results=(0,), output="Successfully signed"):
        self.results, self.output, self.calls, self.pfx_seen = list(results), output, [], []

    def __call__(self, cmd, **kw):
        self.calls.append(cmd)
        pfx = Path(cmd[cmd.index("/f") + 1])
        self.pfx_seen.append((pfx, pfx.is_file() and pfx.stat().st_size > 0))
        rc = self.results.pop(0) if self.results else 0
        return subprocess.CompletedProcess(cmd, rc, self.output if rc == 0 else "", "" if rc == 0 else self.output)


# ------------------------------------------------------------- when signing runs
def test_no_secrets_skips_with_a_notice(capsys, monkeypatch):
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    runner = FakeSigntool()
    result = cs.sign_executables([Path("a.exe")], env={}, runner=runner)
    assert not result.signed and not runner.calls
    assert "::notice title=Code signing::" in capsys.readouterr().out
    assert "not signed" in result.build_info()


def test_empty_secrets_as_on_forks_also_skip():
    assert cs.secrets({"WINDOWS_PFX_BASE64": "", "WINDOWS_PFX_PASSWORD": ""}) is None


@pytest.mark.parametrize("env", [{"WINDOWS_PFX_BASE64": "abc"}, {"WINDOWS_PFX_PASSWORD": "pw"}])
def test_half_configured_secrets_fail(env):
    with pytest.raises(BuildError, match="half configured"):
        cs.secrets(env)


def test_bad_base64_wrong_password_and_unsuitable_certificates_fail_clearly(pfx_b64):
    with pytest.raises(BuildError, match="not valid base64"):
        cs.decode_pfx("not base64!!")
    with pytest.raises(BuildError, match="wrong WINDOWS_PFX_PASSWORD"):
        cs.inspect_pfx(base64.b64decode(pfx_b64), "nope")
    with pytest.raises(BuildError, match="not for code signing"):
        cs.inspect_pfx(make_pfx(eku=False), "pw")
    with pytest.raises(BuildError, match="not now"):
        cs.inspect_pfx(make_pfx(days=(-30, -1)), "pw")


def test_certificate_details(pfx_b64):
    cert = cs.inspect_pfx(base64.b64decode(pfx_b64), "pw")
    assert cert.self_signed and "Driver Installer test" in cert.subject
    assert len(cert.thumbprint) == 40 and cert.thumbprint == cert.thumbprint.upper()
    assert not cs.inspect_pfx(make_pfx(self_signed=False), "pw").self_signed


# ------------------------------------------------------------- what it runs
def test_signs_all_files_with_sha256_and_a_timestamp_then_wipes_the_pfx(pfx_b64, tmp_path, capsys):
    files = [tmp_path / "DriverInstaller.exe", tmp_path / "DriverInstaller-Setup.exe"]
    runner = FakeSigntool()
    env = {"WINDOWS_PFX_BASE64": base64.b64encode(make_pfx(b"s3cret-pw")).decode(), "WINDOWS_PFX_PASSWORD": "s3cret-pw"}
    result = cs.sign_executables(files, env=env, runner=runner, signtool=Path("signtool.exe"), readback=False)
    assert result.signed and result.cert.thumbprint in result.build_info()
    (cmd,) = runner.calls
    joined = " ".join(cmd)
    assert cmd[:2] == ["signtool.exe", "sign"]
    assert "/fd SHA256 /tr http://timestamp.digicert.com /td SHA256" in joined
    assert cmd[-len(files):] == [str(f) for f in files]
    pfx, existed = runner.pfx_seen[0]
    assert existed and not pfx.exists() and not pfx.parent.exists()
    assert "s3cret-pw" not in capsys.readouterr().out          # redacted in the echoed command


def test_pfx_is_deleted_when_signtool_fails(pfx_b64):
    runner = FakeSigntool(results=[1], output="SignTool Error: no certificates were found")
    env = {"WINDOWS_PFX_BASE64": pfx_b64, "WINDOWS_PFX_PASSWORD": "pw"}
    with pytest.raises(BuildError, match="signtool sign failed"):
        cs.sign_executables([Path("a.exe")], env=env, runner=runner, signtool=Path("signtool.exe"), readback=False)
    pfx, existed = runner.pfx_seen[0]
    assert existed and not pfx.exists()


def test_timestamp_failures_are_retried(pfx_b64, monkeypatch):
    monkeypatch.setattr(cs.time, "sleep", lambda s: None)
    runner = FakeSigntool(results=[1, 0], output="SignTool Error: The specified timestamp server could not be reached.")
    env = {"WINDOWS_PFX_BASE64": pfx_b64, "WINDOWS_PFX_PASSWORD": "pw", "WINDOWS_TIMESTAMP_URL": "http://ts.example"}
    assert cs.sign_executables([Path("a.exe")], env=env, runner=runner, signtool=Path("st"), readback=False).signed
    assert len(runner.calls) == 2 and "http://ts.example" in runner.calls[0]
    assert all(not p.exists() for p, _ in runner.pfx_seen)


def test_find_signtool_picks_the_newest_sdk(tmp_path):
    for version in ("10.0.19041.0", "10.0.26100.0", "10.0.22621.0"):
        exe = tmp_path / "Windows Kits" / "10" / "bin" / version / "x64" / "signtool.exe"
        exe.parent.mkdir(parents=True)
        exe.write_bytes(b"MZ")
    found = cs.find_signtool({"ProgramFiles(x86)": str(tmp_path), "PATH": ""}, arch="x64")
    assert "10.0.26100.0" in str(found)
    explicit = tmp_path / "custom-signtool.exe"
    explicit.write_bytes(b"MZ")
    assert cs.find_signtool({"SIGNTOOL": str(explicit)}) == explicit
    with pytest.raises(BuildError, match="Windows SDK"):
        cs.find_signtool({"ProgramFiles(x86)": str(tmp_path / "none"), "PATH": ""}, arch="arm64")


def test_signature_readback_checks_signer_status_and_timestamp(pfx_b64):
    import json
    cert = cs.inspect_pfx(base64.b64decode(pfx_b64), "pw")

    def ps(rows):
        def run(cmd, **kw):
            assert not any(k.upper() == "PSMODULEPATH" for k in kw["env"])
            return subprocess.CompletedProcess(cmd, 0, json.dumps(rows), "")
        return run

    good = {"path": "C:/x/a.exe", "status": "UnknownError", "message": "", "thumbprint": cert.thumbprint, "timestamped": True}
    cs.check_signatures([Path("a.exe")], cert, runner=ps(good))          # self-signed: untrusted root accepted
    for bad, match in [({"thumbprint": "00" * 20}, "expected"), ({"status": "HashMismatch"}, "HashMismatch"),
                       ({"timestamped": False}, "no timestamp")]:
        with pytest.raises(BuildError, match=match):
            cs.check_signatures([Path("a.exe")], cert, runner=ps([{**good, **bad}]))
    cert.self_signed = False
    with pytest.raises(BuildError, match="UnknownError"):
        cs.check_signatures([Path("a.exe")], cert, runner=ps([good]))


# ------------------------------------------------------------- where the build signs
def test_build_signs_before_hashing_and_zipping(tmp_path, monkeypatch):
    bw = load("build_windows")
    order = []

    def fake_run(cmd, **kw):
        app = Path(cmd[cmd.index("--distpath") + 1]) / "DriverInstaller"
        app.mkdir(parents=True)
        order.append("pyinstaller")

    monkeypatch.setattr(bw, "run", fake_run)
    monkeypatch.setattr(bw, "icon_file", lambda work: None)
    monkeypatch.setattr(bw, "sign", lambda app: order.append("sign") or bw.codesign_windows.SigningResult(False, reason="test"))
    monkeypatch.setattr(bw, "verify", lambda app, v: order.append("hash") or {"DriverInstaller.exe": "ab" * 32})
    monkeypatch.setattr(bw, "write_zip", lambda app, target: (order.append("zip"), target.write_bytes(b"PK"), target)[2])
    monkeypatch.setattr(bw, "build_setup", lambda *a: order.append("setup") or None)
    (target,) = bw.build("1.2.3", tmp_path / "out", tmp_path / "work")
    assert order == ["pyinstaller", "sign", "hash", "zip", "setup"] and target.name == bw.ZIP_NAME
    info = (tmp_path / "work" / "dist" / "DriverInstaller" / "BUILD-INFO.txt").read_text()
    assert "Authenticode: not signed (test)" in info and "DriverInstaller.exe" in info


def test_setup_is_compiled_from_the_signed_folder_and_signed_by_inno_setup(tmp_path, monkeypatch, pfx_b64):
    bw = load("build_windows")
    iscc = tmp_path / "ISCC.exe"
    iscc.write_bytes(b"MZ")
    out = tmp_path / "dist"
    out.mkdir()
    ran, signed = [], []
    fake_setup = b"MZ" + b"\0" * 64 + b'<requestedExecutionLevel ' + bw.AS_INVOKER + b"/>" + b"\0" * 64
    monkeypatch.setattr(bw.platform, "system", lambda: "Windows")
    monkeypatch.setenv("ISCC", str(iscc))
    monkeypatch.setenv("WINDOWS_PFX_BASE64", pfx_b64)
    monkeypatch.setenv("WINDOWS_PFX_PASSWORD", "pw")
    monkeypatch.setattr(bw, "run", lambda cmd, **kw: ran.append(cmd) or (out / bw.SETUP_NAME).write_bytes(fake_setup))
    monkeypatch.setattr(bw, "manifest_level", lambda exe: "requireAdministrator"
                        if bw.REQUIRE_ADMIN in exe.read_bytes() else "asInvoker")
    monkeypatch.setattr(bw.codesign_windows, "sign_executables",
                        lambda files: signed.append((files, files[0].read_bytes())))
    target = bw.build_setup(tmp_path / "app", "1.2.3", out, tmp_path / "work", None, "auto")
    (cmd,) = ran
    assert cmd[0] == str(iscc) and cmd[-1] == str(bw.ISS)
    assert "/DAppVersion=1.2.3" in cmd and "/DNumericVersion=1.2.3.0" in cmd and f"/DSourceDir={tmp_path / 'app'}" in cmd
    assert "/DSign" in cmd
    sign_opt = next(c for c in cmd if c.startswith("/Sdisign="))
    assert "codesign_windows.py$q $f" in sign_opt                 # Inno calls our signer for Setup + uninstaller
    # the manifest is switched in place (same size), and only then is Setup signed (again)
    assert target.read_bytes() == fake_setup.replace(bw.AS_INVOKER, bw.REQUIRE_ADMIN)
    assert len(target.read_bytes()) == len(fake_setup)
    assert signed == [([target], target.read_bytes())]
    shim = (tmp_path / "work" / "setup" / "driver-installer.cmd").read_bytes()
    assert b'"%~dp0DriverInstaller.exe" %*\r\n' in shim and b"exit /b %ERRORLEVEL%" in shim


def test_setup_without_secrets_is_unsigned_and_missing_iscc_is_handled(tmp_path, monkeypatch):
    bw = load("build_windows")
    monkeypatch.delenv("WINDOWS_PFX_BASE64", raising=False)
    monkeypatch.delenv("WINDOWS_PFX_PASSWORD", raising=False)
    cmd = bw.iscc_command(Path("ISCC.exe"), "2.0.0+gitabc", Path("app"), Path("s.cmd"), Path("out"), None, False)
    assert "/DSign" not in cmd and not any(c.startswith("/S") for c in cmd) and "/DNumericVersion=2.0.0.0" in cmd
    monkeypatch.setattr(bw.platform, "system", lambda: "Windows")
    monkeypatch.setattr(bw, "find_iscc", lambda env=None: None)
    assert bw.build_setup(tmp_path, "1.0", tmp_path, tmp_path, None, "auto") is None
    with pytest.raises(BuildError, match="iscc"):
        bw.build_setup(tmp_path, "1.0", tmp_path, tmp_path, None, "yes")
    assert bw.build_setup(tmp_path, "1.0", tmp_path, tmp_path, None, "no") is None


def test_signing_cli_refuses_to_report_success_without_secrets(monkeypatch, capsys):
    monkeypatch.delenv("WINDOWS_PFX_BASE64", raising=False)
    monkeypatch.delenv("WINDOWS_PFX_PASSWORD", raising=False)
    assert cs.main(["Setup.exe"]) == 1 and "not set" in capsys.readouterr().err
    assert cs.main([]) == 64


def test_portable_layout_check(tmp_path, monkeypatch):
    bw = load("build_windows")
    monkeypatch.setattr(bw.platform, "system", lambda: "Windows")
    for name in ("DriverInstaller.exe", "_internal", "BUILD-INFO.txt"):
        (tmp_path / name).mkdir()
    bw.check_layout(tmp_path)
    (tmp_path / "install_helper.ps1").write_text("")
    with pytest.raises(BuildError, match="install_helper.ps1"):
        bw.check_layout(tmp_path)


def test_signing_secrets_off_windows_fail_instead_of_silently_skipping(monkeypatch, tmp_path):
    bw = load("build_windows")
    monkeypatch.setattr(bw.platform, "system", lambda: "Linux")
    monkeypatch.delenv("WINDOWS_PFX_BASE64", raising=False)
    monkeypatch.delenv("WINDOWS_PFX_PASSWORD", raising=False)
    assert not bw.sign(tmp_path).signed
    monkeypatch.setenv("WINDOWS_PFX_BASE64", "abc")
    monkeypatch.setenv("WINDOWS_PFX_PASSWORD", "pw")
    with pytest.raises(BuildError, match="only on Windows"):
        bw.sign(tmp_path)


def test_workflow_passes_the_secrets_and_verifies_signatures():
    text = (ROOT / ".github" / "workflows" / "build.yml").read_text()
    assert "WINDOWS_PFX_BASE64: ${{ secrets.WINDOWS_PFX_BASE64 }}" in text
    assert "WINDOWS_PFX_PASSWORD: ${{ secrets.WINDOWS_PFX_PASSWORD }}" in text
    assert "Get-AuthenticodeSignature" in text and "signtool verify /pa" in text
    # verification runs on the unzipped release, before the install test and the upload
    assert text.index("Build DriverInstaller-Windows-Portable.zip and DriverInstaller-Setup.exe") \
        < text.index("Verify the Authenticode") < text.index("Install with DriverInstaller-Setup.exe") \
        < text.index("upload-artifact")
    verify = text[text.index("Verify the Authenticode"):text.index("Install with DriverInstaller-Setup.exe")]
    assert "smoke/DriverInstaller/DriverInstaller.exe" in verify and "dist/DriverInstaller-Setup.exe" in verify
    release = text[text.index("  release:"):]
    for name in ("DriverInstaller-Setup.exe", "DriverInstaller-Windows-Portable.zip"):
        assert name in release
    assert "$SIGNER" in release and "$THUMBPRINT" in release and "driver-installer-windows.zip" not in text
