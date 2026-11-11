"""Manifest authenticity: pinned keys only, expiry, rollback, structural checks."""
import copy
import json

import pytest

import demo
from core import manifest, trust
from core.common import VerificationError
from test_scanner_win import _pkg


def doc(**kw):
    return demo.manifest_shell([_pkg("a.pkg", "pci:8086:2725", "2.0")], **kw)


def test_shipped_pin_set_is_empty_and_therefore_refuses_everything():
    assert trust.PINNED_MANIFEST_KEYS == {}            # no release key exists yet
    raw, sig, _ = demo.sign(doc())
    with pytest.raises(VerificationError, match="no manifest signing key is pinned"):
        manifest.load_manifest(raw, sig)


def test_manifest_signed_by_pinned_key_is_accepted(pin):
    raw, sig = pin(doc())
    assert manifest.load_manifest(raw, sig)["packages"][0]["id"] == "a.pkg"


def test_edited_manifest_and_foreign_key_are_rejected(pin):
    raw, sig = pin(doc())
    with pytest.raises(VerificationError, match="signature is invalid"):
        manifest.load_manifest(raw.replace(b'"2.0"', b'"9.0"'), sig)
    other_raw, other_sig, _ = demo.sign(doc())          # correctly signed, but by a key that is not pinned
    with pytest.raises(VerificationError, match="not made by a pinned key"):
        manifest.load_manifest(other_raw, other_sig)
    with pytest.raises(VerificationError, match="base64"):
        manifest.load_manifest(raw, b"***")


def test_expired_manifest_is_rejected(pin):
    raw, sig = pin(doc(expires_in_days=-1))
    with pytest.raises(VerificationError, match="expired"):
        manifest.load_manifest(raw, sig)


def test_rollback_to_an_older_sequence_is_rejected(tmp_path):
    keys = {}
    signed = {}
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    import base64
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    keys[trust.key_id(pub)] = pub
    for seq in (5, 4):
        raw = json.dumps(doc(sequence=seq)).encode()
        signed[seq] = (raw, base64.b64encode(key.sign(raw)))
    manifest.load_manifest(*signed[5], trusted_keys=keys, seq_dir=tmp_path)
    with pytest.raises(VerificationError, match="rollback"):
        manifest.load_manifest(*signed[4], trusted_keys=keys, seq_dir=tmp_path)
    manifest.load_manifest(*signed[5], trusted_keys=keys, seq_dir=tmp_path)     # same sequence is fine


@pytest.mark.parametrize("mutate,what", [
    (lambda p: p["artifact"].update(url="http://example.invalid/a.zip"), "must be https"),
    (lambda p: p["artifact"].update(sha256="abc"), "sha256"),
    (lambda p: p["artifact"].update(filename="../../evil.zip"), "filename"),
    (lambda p: p["install"].update(inf_path="..\\..\\Windows\\evil.inf"), "inf_path"),
    (lambda p: p["install"].update(inf_path="/abs/evil.inf"), "inf_path"),
    (lambda p: p["install"].update(package_name="-o=APT::Update::Pre-Invoke::=sh"), "package_name"),
    (lambda p: p["install"].update(method="shell"), "install.method"),
    (lambda p: p.update(id="Bad Id"), "package id"),
    (lambda p: p.update(class_guid="not-a-guid"), "class_guid"),
    (lambda p: p.pop("artifact"), "artifact may only be omitted"),
    (lambda p: p["artifact"]["signature"].update(type="none"), "signature.type"),
])
def test_structural_validation_blocks_dangerous_values(mutate, what):
    pkg = copy.deepcopy(_pkg("a.pkg", "pci:8086:2725", "2.0"))
    mutate(pkg)
    with pytest.raises(VerificationError, match=what):
        manifest.validate_package(pkg)


def test_repository_package_needs_no_artifact():
    pkg = _pkg("distro.nvidia", "pci:10de:2684", "550.120")
    del pkg["artifact"]
    pkg["install"] = {"method": "package-manager", "package_name": "nvidia-driver-550", "reboot_required": True}
    manifest.validate_package(pkg)
