"""Verification pipeline: SHA-256 gated downloads, staged copies, Authenticode, GPG.

Order for every package, enforced by engine.py:
  1. signed manifest (manifest.py)            -> what to expect
  2. size + SHA-256 while downloading          -> the bytes are the expected bytes
  3. publisher signature (Authenticode / GPG)  -> the bytes come from the named publisher
  4. the elevated helper repeats 2 and 3 on its own private copy before installing
"""
from __future__ import annotations

import base64
import dataclasses
import hashlib
import hmac
import json
import os
import re
import shutil
import stat
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path

from . import common, trust
from .common import VerificationError
from .manifest import SHA256_RE

CHUNK = 1 << 20


# ------------------------------------------------------------------ SHA-256
def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def safe_name(filename: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", Path(filename).name) or "package.bin"


def _check_url(url: str, allow_loopback_http: bool) -> None:
    parts = urllib.parse.urlsplit(url)
    if parts.scheme == "https":
        return
    if allow_loopback_http and parts.scheme == "http" and parts.hostname in ("127.0.0.1", "localhost", "::1"):
        return  # demo and tests only
    raise VerificationError(f"refusing non-HTTPS URL: {url}")


class RedirectError(VerificationError):
    """A response redirected where the caller asked for none. `location` says where to."""

    def __init__(self, url: str, code: int, location: str):
        super().__init__(f"{url} answered {code}, redirecting to {location}")
        self.url, self.code, self.location = url, code, location


def _opener(allow_loopback_http: bool, follow_redirects: bool = True) -> urllib.request.OpenerDirector:
    class HttpsOnlyRedirects(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            common.audit("net.redirect", to=newurl, code=code)
            if not follow_redirects:
                raise RedirectError(req.full_url, code, newurl)
            _check_url(newurl, allow_loopback_http)
            return super().redirect_request(req, fp, code, msg, headers, newurl)
    opener = urllib.request.build_opener(HttpsOnlyRedirects)
    opener.addheaders = [("User-Agent", f"{common.APP}/{common.VERSION}")]  # no identifiers
    return opener


def _receive(read, out, expected_sha256: str, expected_size: int, progress=None) -> str:
    """Stream `read()` into `out`, enforcing the size cap and returning the verified digest."""
    digest, total = hashlib.sha256(), 0
    while chunk := read(CHUNK):
        total += len(chunk)
        if total > expected_size:
            raise VerificationError(f"data exceeds the declared size of {expected_size} bytes")
        digest.update(chunk)
        out.write(chunk)
        if progress:
            progress(total, expected_size)
    out.flush()
    os.fsync(out.fileno())
    actual = digest.hexdigest()
    if total != expected_size:
        raise VerificationError(f"size mismatch: got {total} bytes, manifest says {expected_size}")
    if not hmac.compare_digest(actual, expected_sha256):
        raise VerificationError(f"SHA-256 MISMATCH: got {actual}, manifest says {expected_sha256}")
    return actual


def private_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        os.chmod(path, 0o700)
    return path


def _gated_write(source_desc: str, opener, dest_dir: Path, expected_sha256: str, expected_size: int,
                 filename: str, progress=None) -> Path:
    """Shared by download and staging: write to a temp file, verify, then rename. Purge on any failure."""
    if not SHA256_RE.match(expected_sha256):
        raise VerificationError("manifest sha256 is malformed")
    private_dir(dest_dir)
    fd, tmp = tempfile.mkstemp(dir=dest_dir, prefix=".partial-")  # 0600, never executable
    try:
        with os.fdopen(fd, "wb") as out, opener() as src:
            actual = _receive(src.read, out, expected_sha256, expected_size, progress)
    except Exception as exc:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        common.audit("verify.rejected", source=source_desc, reason=str(exc), purged=not os.path.exists(tmp))
        if isinstance(exc, VerificationError):
            raise
        raise VerificationError(f"could not read {source_desc}: {exc}") from exc
    final = dest_dir / f"{expected_sha256[:16]}-{safe_name(filename)}"
    os.replace(tmp, final)
    if os.name != "nt":
        os.chmod(final, 0o400)
    common.audit("verify.sha256_ok", source=source_desc, sha256=actual, size=expected_size, path=str(final))
    return final


def secure_download(url: str, expected_sha256: str, expected_size: int, dest_dir: Path, filename: str,
                    *, allow_loopback_http: bool = False, progress=None) -> Path:
    """Download into a private quarantine directory; return the path only if size and SHA-256 match."""
    _check_url(url, allow_loopback_http)
    common.audit("net.request", url=url, expect_sha256=expected_sha256, expect_size=expected_size)
    return _gated_write(url, lambda: _opener(allow_loopback_http).open(url, timeout=30),
                        dest_dir, expected_sha256, expected_size, filename, progress)


def stage_verified_copy(src: Path, dest_dir: Path, expected_sha256: str, expected_size: int, filename: str) -> Path:
    """Copy a file handed over by the unprivileged side into the helper's private directory,
    hashing the bytes as they are copied. What gets installed is the copy, so swapping the
    original after this point has no effect (no time-of-check/time-of-use gap)."""
    def opener():
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
        return os.fdopen(os.open(src, flags), "rb")
    return _gated_write(f"file {src}", opener, dest_dir, expected_sha256, expected_size, filename)


def fetch_small(url: str, dest: Path, *, allow_loopback_http: bool = False, limit: int = 1 << 16) -> Path:
    """Fetch a small signed or signature file (detached signature, manifest). Its integrity
    comes from the signature check that follows, not from this transfer."""
    _check_url(url, allow_loopback_http)
    common.audit("net.request", url=url, kind="signature-or-manifest")
    try:
        with _opener(allow_loopback_http).open(url, timeout=30) as resp:
            data = resp.read(limit + 1)
    except OSError as exc:
        raise VerificationError(f"could not fetch {url}: {exc}") from exc
    if len(data) > limit:
        raise VerificationError(f"{url} is larger than {limit} bytes")
    dest.write_bytes(data)
    return dest


def http_fetch(url: str, *, data: bytes | None = None, limit: int = 8 << 20, timeout: int = 30,
               headers: dict | None = None, allow_loopback_http: bool = False,
               follow_redirects: bool = True) -> bytes:
    """GET (or POST when `data` is given) into memory. HTTPS only, HTTPS-only redirects,
    hard size cap. Used for the LOLDrivers feed and Microsoft Update Catalog pages; nothing
    fetched this way is trusted for its content alone. With follow_redirects=False a 3xx
    answer raises RedirectError instead of quietly fetching the page it points to."""
    _check_url(url, allow_loopback_http)
    common.audit("net.request", url=url, method="POST" if data is not None else "GET")
    req = urllib.request.Request(url, data=data, headers=headers or {})
    try:
        with _opener(allow_loopback_http, follow_redirects).open(req, timeout=timeout) as resp:
            body = resp.read(limit + 1)
    except RedirectError:
        raise
    except (OSError, ValueError) as exc:
        raise VerificationError(f"could not fetch {url}: {exc}") from exc
    if len(body) > limit:
        raise VerificationError(f"{url} returned more than {limit} bytes")
    return body


def download_from_host(url: str, dest_dir: Path, filename: str, *, host_ok, max_size: int,
                       expected_sha1: str | None = None, expected_sha256: str | None = None,
                       allow_loopback_http: bool = False, progress=None) -> tuple[Path, str, int]:
    """Download a file whose hash is not known from a signed manifest (catalog discovery).

    The host must satisfy `host_ok(hostname)` on every hop, the size is capped, and any digest
    the catalog published is checked. Returns (path, sha256, size). The SHA-256 computed here
    is integrity for the rest of the pipeline only; authenticity must come from the publisher
    signature check that follows."""
    def check(u: str) -> None:
        _check_url(u, allow_loopback_http)
        host = urllib.parse.urlsplit(u).hostname or ""
        if not host_ok(host):
            raise VerificationError(f"refusing download from unexpected host: {host}")

    class Redirects(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            check(newurl)
            common.audit("net.redirect", to=newurl, code=code)
            return super().redirect_request(req, fp, code, msg, headers, newurl)

    check(url)
    private_dir(dest_dir)
    opener = urllib.request.build_opener(Redirects)
    opener.addheaders = [("User-Agent", f"{common.APP}/{common.VERSION}")]
    common.audit("net.request", url=url, kind="catalog-download", max_size=max_size)
    fd, tmp = tempfile.mkstemp(dir=dest_dir, prefix=".partial-")
    sha256, sha1, total = hashlib.sha256(), hashlib.sha1(), 0
    try:
        with os.fdopen(fd, "wb") as out, opener.open(url, timeout=60) as resp:
            while chunk := resp.read(CHUNK):
                total += len(chunk)
                if total > max_size:
                    raise VerificationError(f"download exceeds the {max_size} byte limit")
                sha256.update(chunk)
                sha1.update(chunk)
                out.write(chunk)
                if progress:
                    progress(total, max_size)
            out.flush()
            os.fsync(out.fileno())
        if total == 0:
            raise VerificationError("download is empty")
        if expected_sha256 and not hmac.compare_digest(sha256.hexdigest(), expected_sha256.lower()):
            raise VerificationError(f"SHA-256 MISMATCH: got {sha256.hexdigest()}, catalog says {expected_sha256}")
        if expected_sha1 and not hmac.compare_digest(sha1.hexdigest(), expected_sha1.lower()):
            raise VerificationError(f"SHA-1 MISMATCH: got {sha1.hexdigest()}, catalog says {expected_sha1}")
    except Exception as exc:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        common.audit("verify.rejected", source=url, reason=str(exc), purged=not os.path.exists(tmp))
        if isinstance(exc, VerificationError):
            raise
        raise VerificationError(f"download failed: {exc}") from exc
    digest = sha256.hexdigest()
    final = dest_dir / f"{digest[:16]}-{safe_name(filename)}"
    os.replace(tmp, final)
    if os.name != "nt":
        os.chmod(final, 0o400)
    common.audit("verify.downloaded", source=url, sha256=digest, size=total, path=str(final),
                 catalog_digest_checked=bool(expected_sha1 or expected_sha256))
    return final, digest, total


# ------------------------------------------------------- Authenticode (Windows)
_AUTHENTICODE_PS = r"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$s = Get-AuthenticodeSignature -LiteralPath $env:SD_FILE
[pscustomobject]@{
  Status = $s.Status.ToString(); StatusMessage = $s.StatusMessage
  Subject = $s.SignerCertificate.Subject; Issuer = $s.SignerCertificate.Issuer
  Thumbprint = $s.SignerCertificate.Thumbprint
  SignatureType = "$($s.SignatureType)"; TimeStamped = ($null -ne $s.TimeStamperCertificate)
} | ConvertTo-Json -Compress
"""


@dataclasses.dataclass
class AuthenticodeInfo:
    status: str = "Unknown"
    message: str = ""
    subject: str = ""
    issuer: str = ""
    thumbprint: str = ""
    signature_type: str = ""
    timestamped: bool = False

    @property
    def valid(self) -> bool:
        return self.status == "Valid"


def parse_authenticode(text: str) -> AuthenticodeInfo:
    try:
        d = json.loads(text)
    except (ValueError, TypeError):
        return AuthenticodeInfo(message="unparseable verifier output")
    return AuthenticodeInfo(d.get("Status") or "Unknown", d.get("StatusMessage") or "", d.get("Subject") or "",
                            d.get("Issuer") or "", (d.get("Thumbprint") or "").upper(),
                            d.get("SignatureType") or "", bool(d.get("TimeStamped")))


def authenticode_info(path: Path) -> AuthenticodeInfo:
    """Windows trust decision for .exe/.sys/.dll/.cat/.cab/.msi (embedded or catalog signature).

    Get-AuthenticodeSignature calls WinVerifyTrust and returns the signer certificate,
    which is what the publisher pin needs. The path travels in an environment variable.
    """
    res = common.powershell(_AUTHENTICODE_PS, env={"SD_FILE": str(path)})
    if res is None or res.rc != 0:
        return AuthenticodeInfo(message=(common.clean_powershell_error(res.stderr) if res else "PowerShell unavailable"))
    return parse_authenticode(res.stdout)


def parse_dn(dn: str) -> set[tuple[str, str]]:
    """Split an X.500 name into {(ATTR, value)}; handles quoted and escaped commas."""
    parts, cur, quoted, i = [], "", False, 0
    while i < len(dn):
        ch = dn[i]
        if ch == "\\" and i + 1 < len(dn):
            cur += dn[i + 1]
            i += 2
            continue
        if ch == '"':
            quoted = not quoted
        elif ch == "," and not quoted:
            parts.append(cur)
            cur = ""
        else:
            cur += ch
        i += 1
    parts.append(cur)
    out = set()
    for part in parts:
        key, sep, val = part.strip().partition("=")
        if sep and key.strip() and val.strip():
            out.add((key.strip().upper(), val.strip().lower()))
    return out


def subject_matches(expected: str, actual: str) -> bool:
    """Every RDN in `expected` must appear exactly in `actual`. A substring test would let
    'O=Intel Corporation Evil Ltd' pass for 'O=Intel Corporation'."""
    want = parse_dn(expected)
    return bool(want) and want <= parse_dn(actual)


def verify_authenticode(path: Path, subject: str, thumbprint: str | None = None) -> AuthenticodeInfo:
    info = authenticode_info(path)
    ok = info.valid and subject_matches(subject, info.subject) and (
        not thumbprint or hmac.compare_digest(info.thumbprint, thumbprint.upper()))
    common.audit("signature.authenticode", file=str(path), ok=ok, status=info.status, subject=info.subject,
                 thumbprint=info.thumbprint, type=info.signature_type)
    if not ok:
        why = (f"status {info.status} {info.message}".strip() if not info.valid
               else f"signer '{info.subject}' is not the pinned publisher '{subject}'")
        raise VerificationError(f"Authenticode check failed for {Path(path).name}: {why}")
    return info


def verify_catalogs(directory: Path, subject: str, thumbprint: str | None = None) -> list[str]:
    """Verify every .cat in an extracted driver package against the pinned publisher.
    Windows itself checks that the catalog covers the .inf/.sys files when pnputil stages them."""
    cats = sorted(Path(directory).rglob("*.cat"))
    if not cats:
        raise VerificationError("driver package contains no security catalog (.cat)")
    for cat in cats:
        verify_authenticode(cat, subject, thumbprint)
    return [c.name for c in cats]


# ----------------------------------------------------------------- GPG (Linux)
def _dearmor(text: str) -> bytes | None:
    m = re.search(r"-----BEGIN PGP PUBLIC KEY BLOCK-----(.*?)-----END PGP PUBLIC KEY BLOCK-----", text, re.S)
    if not m:
        return None
    body = [ln.strip() for ln in m.group(1).strip().splitlines()]
    if "" in body:
        body = body[body.index("") + 1:]          # drop armor headers
    try:
        return base64.b64decode("".join(ln for ln in body if ln and not ln.startswith("=")))
    except ValueError:
        return None


def trusted_keyring_files(dirs: list[str] | None = None) -> list[Path]:
    """Keyring files from the pinned directories that only root can modify."""
    found = []
    for d in dirs if dirs is not None else trust.GPG_KEYRING_DIRS:
        for f in sorted(Path(d).glob("*")) if Path(d).is_dir() else []:
            try:
                st = f.stat()
            except OSError:
                continue
            if stat.S_ISREG(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o022:
                found.append(f)
    return found


def verify_gpg(path: Path, signature: Path, fingerprint: str, keyrings: list[Path] | None = None) -> None:
    """Detached OpenPGP signature check with gpgv. The signer must be the fingerprint pinned in
    the signed manifest, and its public key must already be in a trusted keyring; nothing is
    fetched from a key server."""
    files = keyrings if keyrings is not None else trusted_keyring_files()
    tmp = Path(tempfile.mkdtemp(prefix="sd-gpg-"))
    try:
        args = ["gpgv", "--homedir", str(tmp), "--status-fd", "1"]
        for n, f in enumerate(files):
            data = f.read_bytes()
            if data.lstrip().startswith(b"-----BEGIN PGP"):  # apt/rpm ship armored keys; gpgv wants binary
                binary = _dearmor(data.decode("ascii", "replace"))
                if not binary:
                    continue
                f = tmp / f"dearmored-{n}.gpg"
                f.write_bytes(binary)
            elif f.suffix not in (".gpg", ".kbx", ".pgp"):
                continue
            args += ["--keyring", str(f)]
        res = common.run(args + [str(signature), str(path)], timeout=120)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    ok, signer = False, ""
    if res and res.rc == 0 and not re.search(r"^\[GNUPG:\] (BADSIG|EXPKEYSIG|REVKEYSIG|ERRSIG)", res.stdout, re.M):
        m = re.search(r"^\[GNUPG:\] VALIDSIG (.+)$", res.stdout, re.M)
        if m:
            fields = m.group(1).split()
            signer = fields[-1].upper()
            ok = fingerprint.upper() in (fields[0].upper(), signer)  # signing subkey or primary key
    common.audit("signature.gpg", file=str(path), ok=ok, signer=signer, keyrings=len(files))
    if not ok:
        raise VerificationError(f"GPG check failed for {Path(path).name}: " + (
            "gpgv is not installed" if res is None else
            f"signed by {signer}, manifest pins {fingerprint}" if signer else
            "no valid signature from a key in the trusted keyrings"))


# ------------------------------------------------------------------ dispatcher
def verify_publisher(pkg: dict, path: Path, signature_file: str | None = None) -> str:
    """Publisher-signature step for a hash-verified artifact. Returns a short description."""
    sig = pkg["artifact"]["signature"]
    if sig["type"] == "authenticode":
        if sig.get("target", "artifact") == "catalog":
            return "catalog signature is checked after extraction, before pnputil runs"
        verify_authenticode(path, sig["subject"], sig.get("certificate_thumbprint"))
        return "Authenticode OK"
    if sig["type"] == "gpg":
        if not signature_file:
            raise VerificationError("detached GPG signature is missing")
        verify_gpg(path, Path(signature_file), sig["fingerprint"])
        return "GPG OK"
    return f"signature checked by {sig['verifier']} at install time"
