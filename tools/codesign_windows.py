"""Authenticode signing of the Windows executables with signtool.exe.

Used by tools/build_windows.py between PyInstaller and packaging, so the SHA-256 sums in
BUILD-INFO.txt, the zip and the release's SHA256SUMS all describe the signed files.

Signing runs only when both secrets are set:

    WINDOWS_PFX_BASE64     the .pfx (PKCS#12: certificate + private key), base64-encoded
    WINDOWS_PFX_PASSWORD   its password

Optional: SIGNTOOL (path to signtool.exe), WINDOWS_TIMESTAMP_URL (RFC 3161 server,
default DigiCert). When neither secret is set (forks, local builds) signing is skipped with
a notice; when only one is set, or the certificate is unusable, the build fails, because that
is a misconfiguration and silently publishing unsigned files would hide it.

The decoded .pfx lives only in a private temporary folder for the duration of the signtool
call and is overwritten and deleted in a `finally` block, also when signing fails.
"""
from __future__ import annotations

import base64
import binascii
import datetime as dt
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from build_common import BuildError, find_windows_tool, powershell

PFX_ENV = "WINDOWS_PFX_BASE64"
PASSWORD_ENV = "WINDOWS_PFX_PASSWORD"
TIMESTAMP_URL = "http://timestamp.digicert.com"
CODE_SIGNING_OID = "1.3.6.1.5.5.7.3.3"
ATTEMPTS = 3                         # the timestamp server is the usual cause of a transient failure
DESCRIPTION = "Driver Installer"
PROJECT_URL = "https://github.com/Codeee-man/driver-installer"


@dataclass
class SigningCert:
    subject: str
    issuer: str
    thumbprint: str                  # SHA-1 of the DER certificate, upper-case hex, as Windows shows it
    not_after: dt.datetime
    self_signed: bool


@dataclass
class SigningResult:
    signed: bool
    cert: SigningCert | None = None
    reason: str = ""

    def build_info(self) -> str:
        if not self.signed:
            return f"Authenticode: not signed ({self.reason})\n"
        c = self.cert
        return (f"Authenticode: signed (SHA-256, RFC 3161 timestamp)\n  subject    {c.subject}\n"
                f"  issuer     {c.issuer}\n  thumbprint {c.thumbprint}\n")


def notice(text: str) -> None:
    """A GitHub Actions annotation when running in Actions, plain text otherwise."""
    prefix = "::notice title=Code signing::" if os.environ.get("GITHUB_ACTIONS") == "true" else "note: "
    print(prefix + text, flush=True)


def secrets(env=None) -> tuple[str, str] | None:
    env = os.environ if env is None else env
    pfx, password = env.get(PFX_ENV, "").strip(), env.get(PASSWORD_ENV, "")
    if not pfx and not password:
        return None
    if not pfx or not password:
        missing = PFX_ENV if not pfx else PASSWORD_ENV
        raise BuildError(f"code signing is half configured: {missing} is empty. Set both secrets, or neither to build unsigned.")
    return pfx, password


def decode_pfx(text: str) -> bytes:
    try:
        data = base64.b64decode(re.sub(r"\s+", "", text), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise BuildError(f"{PFX_ENV} is not valid base64 ({exc})") from None
    if not data:
        raise BuildError(f"{PFX_ENV} decodes to nothing")
    return data


def inspect_pfx(data: bytes, password: str, now: dt.datetime | None = None) -> SigningCert:
    """Open the PKCS#12 before signtool sees it, for errors that say what is wrong."""
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding, pkcs12
    try:
        key, cert, _extra = pkcs12.load_key_and_certificates(data, password.encode())
    except ValueError:
        raise BuildError(f"cannot open the certificate: wrong {PASSWORD_ENV}, or {PFX_ENV} is not a .pfx file") from None
    if key is None or cert is None:
        raise BuildError("the .pfx must contain the code-signing certificate and its private key")
    now = now or dt.datetime.now(dt.timezone.utc)
    if not (cert.not_valid_before_utc <= now <= cert.not_valid_after_utc):
        raise BuildError(f"the signing certificate is valid {cert.not_valid_before_utc:%Y-%m-%d} to "
                         f"{cert.not_valid_after_utc:%Y-%m-%d}, not now")
    try:
        usages = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound:
        usages = None
    if usages is not None and x509.ObjectIdentifier(CODE_SIGNING_OID) not in usages:
        raise BuildError("the certificate is not for code signing (Extended Key Usage lacks 1.3.6.1.5.5.7.3.3)")
    return SigningCert(subject=cert.subject.rfc4514_string(), issuer=cert.issuer.rfc4514_string(),
                       thumbprint=hashlib.sha1(cert.public_bytes(Encoding.DER)).hexdigest().upper(),
                       not_after=cert.not_valid_after_utc, self_signed=cert.subject == cert.issuer)


def _sdk_version(path: Path) -> tuple[int, ...]:
    m = re.search(r"\\?(\d+(?:\.\d+)+)[\\/]", str(path))
    return tuple(int(p) for p in m.group(1).split(".")) if m else (0,)


def find_signtool(env=None, arch: str | None = None) -> Path:
    """SIGNTOOL, then PATH, then the newest Windows 10/11 SDK under Program Files."""
    arch = arch or ("arm64" if platform.machine().lower() in ("arm64", "aarch64") else "x64")
    candidates = find_windows_tool("signtool", "SIGNTOOL", (f"Windows Kits/10/bin/*/{arch}/signtool.exe",
                                                            f"Windows Kits/10/bin/{arch}/signtool.exe"), env)
    if not candidates:
        raise BuildError("signtool.exe not found: install the Windows SDK (Signing Tools) or set SIGNTOOL")
    return max(candidates, key=_sdk_version)


def _wipe(path: Path) -> None:
    """Overwrite, then delete. On SSDs and copy-on-write file systems the overwrite is
    best effort; the real protection is that the file only ever exists on a throwaway runner
    in a folder only this account can read."""
    try:
        size = path.stat().st_size
        with open(path, "r+b", buffering=0) as fh:
            fh.write(os.urandom(size))
            fh.flush()
            os.fsync(fh.fileno())
    except OSError:
        pass
    try:
        path.unlink()
    except FileNotFoundError:
        pass


def _redact(cmd: list[str], password: str) -> str:
    return " ".join("***" if c == password else str(c) for c in cmd)


def sign_command(signtool: Path, pfx: Path, password: str, files: list[Path], timestamp_url: str) -> list[str]:
    return [str(signtool), "sign", "/fd", "SHA256", "/tr", timestamp_url, "/td", "SHA256",
            "/f", str(pfx), "/p", password, "/d", DESCRIPTION, "/du", PROJECT_URL, "/v",
            *[str(f) for f in files]]


def _run_signtool(cmd: list[str], password: str, runner) -> None:
    for attempt in range(1, ATTEMPTS + 1):
        print("+ " + _redact(cmd, password), flush=True)
        res = runner(cmd, capture_output=True, text=True, timeout=600)
        output = ((res.stdout or "") + (res.stderr or "")).replace(password, "***")
        print(output, end="" if output.endswith("\n") else "\n", flush=True)
        if res.returncode == 0:
            return
        if attempt < ATTEMPTS and re.search(r"timestamp", output, re.I):
            print(f"signtool: timestamp server problem, retrying ({attempt}/{ATTEMPTS})", flush=True)
            time.sleep(5 * attempt)
            continue
        raise BuildError(f"signtool sign failed with exit code {res.returncode}")


READBACK = r"""
$ErrorActionPreference = 'Stop'
$files = ConvertFrom-Json $env:DI_SIGNED_FILES
@($files | ForEach-Object {
  $s = Get-AuthenticodeSignature -LiteralPath $_
  [pscustomobject]@{ path = $_; status = [string]$s.Status; message = $s.StatusMessage;
                     thumbprint = $(if ($s.SignerCertificate) { $s.SignerCertificate.Thumbprint } else { '' });
                     timestamped = [bool]$s.TimeStamperCertificate }
}) | ConvertTo-Json -Compress
"""


def check_signatures(files: list[Path], cert: SigningCert, runner=subprocess.run) -> None:
    """Read each signature back with Get-AuthenticodeSignature: signed by our certificate,
    timestamped, and the file hash matches. A self-signed certificate is not trusted on the
    build machine, so for it 'UnknownError' (untrusted root) is accepted here; the build
    workflow trusts it on the throwaway runner and then requires 'Valid'."""
    res = powershell(READBACK, {**os.environ, "DI_SIGNED_FILES": json.dumps([str(f) for f in files])}, runner)
    if res.returncode != 0:
        raise BuildError(f"Get-AuthenticodeSignature failed: {res.stderr.strip()}")
    rows = json.loads(res.stdout)
    rows = rows if isinstance(rows, list) else [rows]
    allowed = {"Valid", "UnknownError"} if cert.self_signed else {"Valid"}
    for row in rows:
        name = Path(row["path"]).name
        if row["thumbprint"].upper() != cert.thumbprint:
            raise BuildError(f"{name}: signed by {row['thumbprint'] or 'nobody'}, expected {cert.thumbprint}")
        if row["status"] not in allowed:
            raise BuildError(f"{name}: signature status {row['status']}: {row['message']}")
        if not row["timestamped"]:
            raise BuildError(f"{name}: signature has no timestamp")
        print(f"signed {name}: {row['status']}, timestamped, {cert.thumbprint}", flush=True)


def sign_executables(files: list[Path], env=None, runner=subprocess.run, signtool: Path | None = None,
                     readback: bool | None = None) -> SigningResult:
    env = os.environ if env is None else env
    creds = secrets(env)
    if creds is None:
        reason = f"{PFX_ENV} and {PASSWORD_ENV} are not set"
        notice(f"{reason}; building UNSIGNED executables (expected on forks and local builds).")
        return SigningResult(False, reason=reason)
    pfx_text, password = creds
    data = decode_pfx(pfx_text)
    cert = inspect_pfx(data, password)
    signtool = signtool or find_signtool(env)
    if cert.self_signed:
        notice(f"the certificate {cert.subject} is self-signed: Windows shows the publisher only where it is trusted.")
    print(f"signing {len(files)} file(s) with {signtool} as {cert.subject} ({cert.thumbprint})", flush=True)
    tmpdir = Path(tempfile.mkdtemp(prefix="di-sign-"))   # 0700 on POSIX; owner-only profile TEMP on Windows
    pfx = tmpdir / "signing.pfx"
    try:
        fd = os.open(pfx, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        url = env.get("WINDOWS_TIMESTAMP_URL") or TIMESTAMP_URL
        _run_signtool(sign_command(signtool, pfx, password, files, url), password, runner)
    finally:
        _wipe(pfx)
        shutil.rmtree(tmpdir, ignore_errors=True)
    if readback if readback is not None else platform.system() == "Windows":
        check_signatures(files, cert, runner)
    return SigningResult(True, cert=cert)


def configured(env=None) -> SigningCert | None:
    """The signing certificate when both secrets are set (validated), else None."""
    creds = secrets(env)
    return inspect_pfx(decode_pfx(creds[0]), creds[1]) if creds else None


def iscc_signtool(python: str = sys.executable, script: Path | None = None) -> str:
    """The /S option that makes Inno Setup sign Setup.exe and its uninstaller through this
    script (so the same secrets, checks and PFX wiping apply). $q is a quote, $f the file."""
    script = script or Path(__file__).resolve()
    return f"/Sdisign=$q{python}$q $q{script}$q $f"


def verify_signed(files: list[Path], runner=subprocess.run) -> SigningCert:
    """For files signed elsewhere (Inno Setup's compile step): same read-back as after signing."""
    cert = configured()
    if cert is None:
        raise BuildError("verify_signed needs the signing secrets")
    check_signatures(files, cert, runner)
    return cert


def main(argv: list[str]) -> int:
    """py tools\\codesign_windows.py FILE...: sign files with the configured certificate.
    Also Inno Setup's SignTool command. Without the secrets this fails: a caller that asks for a
    signature must not get an unsigned file and exit code 0."""
    if not argv:
        print("usage: codesign_windows.py FILE.exe [FILE.exe ...]", file=sys.stderr)
        return 64
    try:
        if secrets() is None:
            raise BuildError(f"{PFX_ENV} and {PASSWORD_ENV} are not set")
        result = sign_executables([Path(a) for a in argv])
    except BuildError as exc:
        print(f"codesign_windows: {exc}", file=sys.stderr)
        return 1
    print(result.build_info(), end="")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
