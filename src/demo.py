"""Demo mode: a throwaway signing key, a loopback web server and fake payloads.

It exists so the Scan -> Verify flow can be shown without a real manifest. One
package verifies; the other has a deliberately wrong hash. Demo mode can never
install: engine.apply() refuses, and the elevated helper would reject the
throwaway key anyway because it is not pinned in core/trust.py.
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import http.server
import json
import os
import threading
from pathlib import Path

from core import common, engine, manifest
from core.model import Device


def serve(directory: Path):
    class Quiet(http.server.SimpleHTTPRequestHandler):
        def log_message(self, *args):
            pass
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), lambda *a, **k: Quiet(*a, directory=str(directory), **k))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


def sign(document: dict):
    """Returns (raw_bytes, base64_signature, {key_id: public_hex}) using a fresh key."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from core import trust
    key = Ed25519PrivateKey.generate()
    raw = json.dumps(document, indent=1).encode()
    pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    return raw, base64.b64encode(key.sign(raw)), {trust.key_id(pub): pub}


def manifest_shell(packages: list[dict], *, expires_in_days: int = 7, sequence: int = 1) -> dict:
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    stamp = lambda t: t.isoformat().replace("+00:00", "Z")
    return {"schema_version": "1.1", "sequence": sequence, "generated": stamp(now),
            "expires": stamp(now + dt.timedelta(days=expires_in_days)),
            "publisher": {"name": "DEMO - throwaway key, fake payloads"},
            "signing": {"algorithm": "ed25519", "key_id": "0" * 16}, "packages": packages}


def build(devices: list[Device], workdir: Path) -> engine.Context:
    server, base = serve(workdir)
    packages = []
    for i, dev in enumerate([d for d in devices if d.hardware_ids][:2]):
        payload = os.urandom(256 * 1024)
        (workdir / f"demo-{i}.zip").write_bytes(payload)
        sha = hashlib.sha256(payload if i == 0 else payload + b"tampered").hexdigest()
        label = "DEMO good package" if i == 0 else "DEMO tampered package"
        packages.append({
            "id": f"demo.package.{i}", "name": f"{label} for {dev.name[:40]}", "vendor": "Demo",
            "category": "driver", "version": "999.0.0",
            "platform": {"os": common.OS_NAME, "arch": [common.ARCH]}, "hardware_ids": [dev.hardware_ids[0]],
            "artifact": {"url": f"{base}/demo-{i}.zip", "filename": f"demo-{i}.zip", "size": len(payload),
                         "sha256": sha, "format": "zip", "signature": {"type": "delegated", "verifier": "fwupd"}},
            "install": {"method": "pnputil" if common.OS_NAME == "windows" else "fwupd", "reboot_required": False},
            "upstream": {"source": "vendor", "reference_url": "https://example.invalid/demo"}})
    raw, sig, keys = sign(manifest_shell(packages))
    ctx = engine.Context(manifest=manifest.load_manifest(raw, sig, trusted_keys=keys, check_rollback=False,
                                                         loopback_ok=True),
                         manifest_raw=raw, signature=sig, quarantine=workdir / "quarantine",
                         allow_loopback_http=True, demo=True)
    ctx._server = server  # keep the loopback server alive for the session
    return ctx
