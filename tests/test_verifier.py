"""SHA-256 gate, staged copies, Authenticode and GPG."""
import hashlib
import os
import shutil
import subprocess

import pytest

import demo
from conftest import authenticode_json
from core import common, verifier
from core.common import VerificationError

PAYLOAD = os.urandom(2 * verifier.CHUNK + 77)
SHA = hashlib.sha256(PAYLOAD).hexdigest()


@pytest.fixture
def server(tmp_path):
    root = tmp_path / "www"
    root.mkdir()
    (root / "good.cab").write_bytes(PAYLOAD)
    (root / "big.cab").write_bytes(PAYLOAD + b"x" * 4096)
    srv, base = demo.serve(root)
    yield base
    srv.shutdown()


def dl(base, name, sha, size, q, **kw):
    return verifier.secure_download(f"{base}/{name}", sha, size, q, name, allow_loopback_http=True, **kw)


def test_download_accepts_matching_hash_and_stores_read_only(server, tmp_path):
    path = dl(server, "good.cab", SHA, len(PAYLOAD), tmp_path / "q")
    assert path.read_bytes() == PAYLOAD and path.name.startswith(SHA[:16])
    if os.name != "nt":                                 # Windows has no mode bits; the folder is per-user
        assert not os.stat(path).st_mode & 0o333       # no write or execute bits


@pytest.mark.parametrize("name,sha,delta,message", [
    ("good.cab", "0" * 64, 0, "SHA-256 MISMATCH"),
    ("big.cab", SHA, 0, "exceeds the declared size"),
    ("good.cab", SHA, 1, "size mismatch"),
])
def test_download_rejects_and_purges(server, tmp_path, name, sha, delta, message):
    q = tmp_path / "q"
    with pytest.raises(VerificationError, match=message):
        dl(server, name, sha, len(PAYLOAD) + delta, q)
    assert list(q.iterdir()) == []                     # nothing left behind, not even a partial file


def test_non_https_is_refused_before_any_request(server, tmp_path):
    with pytest.raises(VerificationError, match="non-HTTPS"):
        verifier.secure_download("http://example.invalid/x.cab", SHA, 1, tmp_path / "q", "x.cab")
    with pytest.raises(VerificationError, match="non-HTTPS"):      # loopback only when explicitly allowed
        verifier.secure_download(f"{server}/good.cab", SHA, len(PAYLOAD), tmp_path / "q", "g.cab")
    with pytest.raises(VerificationError, match="malformed"):
        verifier.secure_download("https://example.invalid/x", "XYZ", 1, tmp_path / "q", "x")


def test_stage_verified_copy_detects_a_swapped_file(tmp_path):
    src = tmp_path / "pkg.zip"
    src.write_bytes(PAYLOAD)
    staged = verifier.stage_verified_copy(src, tmp_path / "stage", SHA, len(PAYLOAD), "pkg.zip")
    assert staged.read_bytes() == PAYLOAD
    src.write_bytes(PAYLOAD[:-1] + b"!")                # attacker swaps the file after the user-side check
    with pytest.raises(VerificationError, match="SHA-256 MISMATCH"):
        verifier.stage_verified_copy(src, tmp_path / "stage2", SHA, len(PAYLOAD), "pkg.zip")
    assert list((tmp_path / "stage2").iterdir()) == []


@pytest.mark.skipif(not hasattr(os, "O_NOFOLLOW"), reason="needs O_NOFOLLOW")
def test_stage_verified_copy_does_not_follow_symlinks(tmp_path):
    real = tmp_path / "real"
    real.write_bytes(PAYLOAD)
    (tmp_path / "link").symlink_to(real)
    with pytest.raises(VerificationError):
        verifier.stage_verified_copy(tmp_path / "link", tmp_path / "stage", SHA, len(PAYLOAD), "p")


# ---------------------------------------------------------------- Authenticode
@pytest.mark.parametrize("expected,actual,ok", [
    ("O=Intel Corporation", "CN=Intel Corporation, O=Intel Corporation, L=Santa Clara, S=California, C=US", True),
    ("o=intel corporation, c=us", "CN=Intel Corporation, O=Intel Corporation, C=US", True),
    ("O=Intel Corporation", "CN=x, O=Intel Corporation Evil Ltd, C=US", False),     # substring must not pass
    ("O=Intel Corporation", "CN=O=Intel Corporation, O=Evil, C=US", False),
    ('O="Realtek Semiconductor Corp., Ltd"', 'CN=Realtek, O="Realtek Semiconductor Corp., Ltd", C=TW', True),
    ("O=Realtek Semiconductor Corp.\\, Ltd", 'O="Realtek Semiconductor Corp., Ltd"', True),
    ("O=Intel Corporation", "", False),
    ("", "O=Intel Corporation", False),
])
def test_subject_matching_is_exact_per_rdn(expected, actual, ok):
    assert verifier.subject_matches(expected, actual) is ok


def test_authenticode_accepts_valid_pinned_signer(runner, windows, tmp_path):
    runner.on("powershell", common.Result(0, authenticode_json()))
    info = verifier.verify_authenticode(tmp_path / "x.cat", "O=Intel Corporation", "0123456789abcdef0123456789abcdef01234567")
    assert info.valid and info.signature_type == "Authenticode"
    assert runner.calls[0][2]["SD_FILE"].endswith("x.cat")       # the path goes in by env, not by string building


@pytest.mark.parametrize("response,subject,thumb,why", [
    (authenticode_json(status="NotSigned", subject=""), "O=Intel Corporation", None, "status NotSigned"),
    (authenticode_json(status="HashMismatch"), "O=Intel Corporation", None, "status HashMismatch"),
    (authenticode_json(subject="CN=Evil, O=Evil Corp"), "O=Intel Corporation", None, "not the pinned publisher"),
    (authenticode_json(), "O=Intel Corporation", "F" * 40, "not the pinned publisher"),
    ("not json at all", "O=Intel Corporation", None, "status Unknown"),
])
def test_authenticode_rejections(runner, windows, tmp_path, response, subject, thumb, why):
    runner.on("powershell", common.Result(0, response))
    with pytest.raises(VerificationError, match=why):
        verifier.verify_authenticode(tmp_path / "x.sys", subject, thumb)


def test_authenticode_fails_closed_without_powershell(runner, windows, tmp_path):
    runner.available.discard("powershell")
    with pytest.raises(VerificationError):
        verifier.verify_authenticode(tmp_path / "x.exe", "O=Intel Corporation")


def test_catalog_check_requires_a_catalog_and_checks_each(runner, windows, tmp_path):
    with pytest.raises(VerificationError, match="no security catalog"):
        verifier.verify_catalogs(tmp_path, "O=Intel Corporation")
    (tmp_path / "a.cat").write_bytes(b"1")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b.cat").write_bytes(b"2")
    runner.on("powershell", common.Result(0, authenticode_json()))
    assert verifier.verify_catalogs(tmp_path, "O=Intel Corporation") == ["a.cat", "b.cat"]
    assert len(runner.ran("powershell")) == 2


# ------------------------------------------------------------------------ GPG
@pytest.fixture(scope="module")
def gpg(tmp_path_factory):
    """A real throwaway OpenPGP key, exported to binary and armored keyrings."""
    if os.name == "nt" or not (shutil.which("gpg") and shutil.which("gpgv")):
        pytest.skip("GPG verification is the Linux path; needs gpg and gpgv")
    home = tmp_path_factory.mktemp("gnupg")
    os.chmod(home, 0o700)
    env = {**os.environ, "GNUPGHOME": str(home)}

    def g(*args, **kw):
        return subprocess.run(["gpg", "--batch", "--quiet", "--pinentry-mode", "loopback", "--passphrase", "", *args],
                              env=env, check=True, capture_output=True, **kw)
    g("--quick-generate-key", "SafeDriver Test <test@example.invalid>", "ed25519", "sign", "never")
    listing = g("--with-colons", "--fingerprint").stdout.decode()
    fingerprint = next(line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr"))
    work = tmp_path_factory.mktemp("gpgfiles")
    (work / "vendor.gpg").write_bytes(g("--export").stdout)
    (work / "vendor.asc").write_bytes(g("--armor", "--export").stdout)
    pkg = work / "tools.deb"
    pkg.write_bytes(PAYLOAD)
    g("--detach-sign", "-o", str(work / "tools.deb.sig"), str(pkg))
    subprocess.run(["gpgconf", "--kill", "all"], env=env, capture_output=True)
    return {"dir": work, "fpr": fingerprint, "pkg": pkg, "sig": work / "tools.deb.sig"}


def test_gpg_accepts_pinned_signer_from_binary_and_armored_keyrings(gpg):
    verifier.verify_gpg(gpg["pkg"], gpg["sig"], gpg["fpr"], keyrings=[gpg["dir"] / "vendor.gpg"])
    verifier.verify_gpg(gpg["pkg"], gpg["sig"], gpg["fpr"].lower(), keyrings=[gpg["dir"] / "vendor.asc"])


def test_gpg_rejects_tampered_file_wrong_pin_and_unknown_key(gpg, tmp_path):
    tampered = tmp_path / "tools.deb"
    tampered.write_bytes(PAYLOAD + b"!")
    with pytest.raises(VerificationError, match="no valid signature"):
        verifier.verify_gpg(tampered, gpg["sig"], gpg["fpr"], keyrings=[gpg["dir"] / "vendor.gpg"])
    with pytest.raises(VerificationError, match="manifest pins"):       # valid signature, but not the pinned key
        verifier.verify_gpg(gpg["pkg"], gpg["sig"], "A" * 40, keyrings=[gpg["dir"] / "vendor.gpg"])
    with pytest.raises(VerificationError, match="no valid signature"):  # key not in any trusted keyring
        verifier.verify_gpg(gpg["pkg"], gpg["sig"], gpg["fpr"], keyrings=[])


@pytest.mark.skipif(os.name == "nt", reason="GPG keyrings are a Linux feature; POSIX ownership")
def test_keyring_discovery_ignores_files_others_can_write(tmp_path):
    good, bad = tmp_path / "good.gpg", tmp_path / "bad.gpg"
    good.write_bytes(b"k")
    bad.write_bytes(b"k")
    os.chmod(good, 0o644)
    os.chmod(bad, 0o666)
    found = verifier.trusted_keyring_files([str(tmp_path), str(tmp_path / "missing")])
    assert found == ([good] if os.geteuid() == 0 else [])          # must also be owned by root


def test_verify_publisher_dispatch(runner, windows, tmp_path):
    art = {"signature": {"type": "authenticode", "subject": "O=X", "target": "catalog"}}
    assert "after extraction" in verifier.verify_publisher({"artifact": art}, tmp_path / "a.zip")
    assert runner.calls == []
    with pytest.raises(VerificationError, match="missing"):
        verifier.verify_publisher({"artifact": {"signature": {"type": "gpg", "fingerprint": "A" * 40}}}, tmp_path / "a")
    assert "fwupd" in verifier.verify_publisher({"artifact": {"signature": {"type": "delegated", "verifier": "fwupd"}}},
                                                tmp_path / "a")
