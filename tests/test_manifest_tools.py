"""tools/build_manifest.py and tools/sign_manifest.py: a driver folder becomes a signed manifest
that loads exactly as a client loads it; both tools read the same key formats."""
import base64
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
build_manifest = pytest.importorskip("build_manifest")
import sign_manifest  # noqa: E402
from core import manifest as manifest_mod, trust  # noqa: E402

INF = """[Version]
Signature="$WINDOWS NT$"
Class=Net
ClassGuid={4d36e972-e325-11ce-bfc1-08002be10318}
Provider=%Vendor%
DriverVer=05/01/2026,1.2.3.4
CatalogFile=netx.cat

[Manufacturer]
%Vendor%=Models,NTamd64

[Models.NTamd64]
%Desc%=Install, PCI\\VEN_8086&DEV_1234

[Strings]
Vendor="Example Corp"
Desc="Example NIC"
"""


@pytest.fixture
def keys(tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key = Ed25519PrivateKey.generate()
    hex_file, pem_file = tmp_path / "key.hex", tmp_path / "key.pem"
    hex_file.write_text(key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                          serialization.NoEncryption()).hex())
    pem_file.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    return hex_file, pem_file, public


def test_driver_folder_becomes_a_signed_manifest_both_tools_agree_on(tmp_path, keys, capsys):
    hex_file, pem_file, public = keys
    drivers = tmp_path / "drivers" / "net"
    drivers.mkdir(parents=True)
    (drivers / "netx.inf").write_text(INF)
    (drivers / "netx.sys").write_bytes(b"sys")
    (drivers / "netx.cat").write_bytes(b"cat")
    (tmp_path / "drivers" / "loose.fw").write_bytes(b"fw")
    out = tmp_path / "out" / "manifest.json"
    assert build_manifest.main(["--driver-dir", str(tmp_path / "drivers"), "--url-prefix", "https://dl.example.org/d",
                                "--private-key", str(hex_file), "--output", str(out),
                                "--publisher", "O=Example Corp"]) == 0
    raw, sig = out.read_bytes(), out.with_name("manifest.json.sig").read_bytes().strip()
    key_id = trust.key_id(public)
    doc = manifest_mod.load_manifest(raw, sig, trusted_keys={key_id: public}, check_rollback=False)
    (pkg,) = doc["packages"]
    assert pkg["version"] == "1.2.3.4" and pkg["artifact"]["url"].startswith("https://dl.example.org/d/")
    inventory = json.loads(out.with_name("manifest.files.json").read_text())
    assert inventory["loose.fw"]["in_manifest"] is False and inventory["net/netx.sys"]["in_manifest"]
    # sign_manifest with the PEM form of the same key gives the same (deterministic) signature
    out.with_name("manifest.json.sig").unlink()
    assert sign_manifest.main(["--key", str(pem_file), str(out)]) == 0
    assert out.with_name("manifest.json.sig").read_bytes().strip() == sig
    assert base64.b64decode(sig)


def test_bad_keys_are_refused_without_writing(tmp_path, capsys):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    rsa_pem = tmp_path / "rsa.pem"
    rsa_pem.write_bytes(rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    junk = tmp_path / "junk.key"
    junk.write_text("not a key")
    manifest = tmp_path / "manifest.json"
    manifest.write_text('{"packages": []}')
    for key in (rsa_pem, junk):
        assert sign_manifest.main(["--key", str(key), str(manifest)]) == 2
    assert "Ed25519" in capsys.readouterr().err
    assert not manifest.with_name("manifest.json.sig").exists()
