"""Live BYOVD protection: block drivers listed by the LOLDrivers project.

"Bring your own vulnerable driver" attacks load a legitimately signed but exploitable
(or outright malicious) kernel driver. A valid signature therefore proves nothing about
safety, so every .sys in a driver package is also checked against https://www.loldrivers.io.

  * `fetch()` downloads the feed into memory immediately before installation. Nothing is
    cached on disk, so a stale or tampered local copy can never be consulted.
  * Lookups are dictionary lookups: O(1) per hash, whatever the size of the feed.
  * A hit raises `SecurityAlert`. The caller aborts the whole install plan and purges files.
  * If the feed cannot be fetched, or looks implausibly small, `BlocklistUnavailable` is
    raised: callers stop and ask instead of silently installing unchecked drivers.

Limits: matching is on the file's SHA-256 (plus SHA-1/MD5 for entries that publish only
those). Entries that list only an Authenticode hash, and drivers not yet known to the
project, are not caught. This is one layer, next to signatures and Windows' own blocklist.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
import shutil
import tempfile
import zipfile
from pathlib import Path

from .. import common, verifier
from ..common import VerificationError

URL = "https://www.loldrivers.io/api/drivers.json"
MAX_FEED_BYTES = 256 << 20
MIN_HASHES = 500          # the real feed has thousands; fewer means truncated or tampered
_HEX_LENGTH = {"SHA256": 64, "SHA1": 40, "MD5": 32}


class BlocklistUnavailable(Exception):
    """The LOLDrivers feed could not be fetched or did not look like the real feed."""


class SecurityAlert(VerificationError):
    """A driver file matches a known vulnerable or malicious driver."""

    def __init__(self, matches: list[dict]):
        self.matches = matches
        first = matches[0]
        more = f" (+{len(matches) - 1} more)" if len(matches) > 1 else ""
        super().__init__(f"SECURITY ALERT: {first['file']} is a known {first['category']} "
                         f"(LOLDrivers {first['driver_id']}, sha256 {first['sha256']}){more}. Installation aborted.")


@dataclasses.dataclass(frozen=True)
class BlockEntry:
    driver_id: str
    category: str          # "vulnerable driver" | "malicious"
    name: str


class Blocklist:
    """Hash -> entry maps held in memory only."""

    def __init__(self):
        self.by_hash: dict[str, dict[str, BlockEntry]] = {"SHA256": {}, "SHA1": {}, "MD5": {}}
        self.drivers = 0

    def __len__(self) -> int:
        return sum(len(m) for m in self.by_hash.values())

    def add(self, algorithm: str, value, entry: BlockEntry) -> None:
        if isinstance(value, str):
            value = value.strip().lower()
            if len(value) == _HEX_LENGTH[algorithm] and all(c in "0123456789abcdef" for c in value):
                self.by_hash[algorithm].setdefault(value, entry)

    def lookup(self, sha256: str, sha1: str | None = None, md5: str | None = None) -> BlockEntry | None:
        """O(1): at most three dictionary lookups."""
        return (self.by_hash["SHA256"].get(sha256.lower())
                or (self.by_hash["SHA1"].get(sha1.lower()) if sha1 else None)
                or (self.by_hash["MD5"].get(md5.lower()) if md5 else None))


def parse(raw: bytes, minimum: int = MIN_HASHES) -> Blocklist:
    try:
        data = json.loads(raw)
    except ValueError as exc:
        raise BlocklistUnavailable(f"LOLDrivers feed is not valid JSON: {exc}") from exc
    if isinstance(data, dict):
        data = data.get("drivers") or data.get("data") or []
    if not isinstance(data, list):
        raise BlocklistUnavailable("LOLDrivers feed has an unexpected shape")
    blocklist = Blocklist()
    for driver in data:
        if not isinstance(driver, dict):
            continue
        tags = driver.get("Tags") or []
        base = BlockEntry(str(driver.get("Id") or "?"), str(driver.get("Category") or "vulnerable driver").lower(),
                          str(tags[0]) if isinstance(tags, list) and tags else "")
        blocklist.drivers += 1
        for sample in driver.get("KnownVulnerableSamples") or []:
            if not isinstance(sample, dict):
                continue
            entry = dataclasses.replace(base, name=str(sample.get("Filename") or sample.get("OriginalFilename")
                                                       or base.name))
            for algorithm in _HEX_LENGTH:
                blocklist.add(algorithm, sample.get(algorithm), entry)
    if len(blocklist) < minimum:
        raise BlocklistUnavailable(f"LOLDrivers feed holds only {len(blocklist)} hashes (expected at least "
                                   f"{minimum}); treating it as truncated or tampered")
    return blocklist


def fetch(url: str | None = None, *, timeout: int = 90, allow_loopback_http: bool = False,
          minimum: int = MIN_HASHES) -> Blocklist:
    """Download and parse the feed in memory. Raises BlocklistUnavailable on any problem."""
    try:
        raw = verifier.http_fetch(url or URL, limit=MAX_FEED_BYTES, timeout=timeout,
                                  allow_loopback_http=allow_loopback_http)
    except VerificationError as exc:
        common.audit("blocklist.unavailable", reason=str(exc))
        raise BlocklistUnavailable(str(exc)) from exc
    try:
        blocklist = parse(raw, minimum)
    except BlocklistUnavailable as exc:
        common.audit("blocklist.unavailable", reason=str(exc))
        raise
    common.audit("blocklist.loaded", drivers=blocklist.drivers, hashes=len(blocklist),
                 feed_sha256=hashlib.sha256(raw).hexdigest())
    return blocklist


def _digests(stream) -> dict[str, str]:
    hashers = {"sha256": hashlib.sha256(), "sha1": hashlib.sha1(), "md5": hashlib.md5()}  # noqa: S324 - lookup keys
    while chunk := stream.read(1 << 20):
        for h in hashers.values():
            h.update(chunk)
    return {name: h.hexdigest() for name, h in hashers.items()}


def _judge(name: str, digests: dict[str, str], blocklist: Blocklist, checked: list, matches: list) -> None:
    checked.append({"file": name, "sha256": digests["sha256"]})
    hit = blocklist.lookup(digests["sha256"], digests["sha1"], digests["md5"])
    if hit:
        matches.append({"file": name, "sha256": digests["sha256"], "driver_id": hit.driver_id,
                        "category": hit.category, "known_as": hit.name})


def _finish(source: str, checked: list, matches: list) -> list[dict]:
    if matches:
        common.audit("security.alert", source=source, matches=matches)
        raise SecurityAlert(matches)
    common.audit("blocklist.checked", source=source, sys_files=len(checked))
    return checked


def check_directory(directory: Path, blocklist: Blocklist) -> list[dict]:
    """Hash every .sys under `directory` and compare. Returns the files checked; raises SecurityAlert."""
    checked, matches = [], []
    for path in sorted(p for p in Path(directory).rglob("*") if p.is_file() and p.suffix.lower() == ".sys"):
        with open(path, "rb") as fh:
            _judge(path.relative_to(directory).as_posix(), _digests(fh), blocklist, checked, matches)
    return _finish(str(directory), checked, matches)


def check_archive(path: Path, fmt: str, blocklist: Blocklist) -> list[dict] | None:
    """Check the .sys files inside a downloaded driver package before it is staged.

    .zip members are hashed straight from the archive, without extracting. .cab files are
    unpacked with Windows' expand.exe into a temporary directory that is always removed.
    Returns None when the archive cannot be opened here (a .cab on a non-Windows host):
    the elevated helper repeats this check on the extracted package in every case."""
    if fmt == "zip":
        checked, matches = [], []
        try:
            with zipfile.ZipFile(path) as zf:
                for info in zf.infolist():
                    if not info.is_dir() and info.filename.lower().endswith(".sys"):
                        with zf.open(info) as member:
                            _judge(info.filename, _digests(member), blocklist, checked, matches)
        except (zipfile.BadZipFile, OSError) as exc:
            raise VerificationError(f"{Path(path).name} is not a readable zip archive: {exc}") from exc
        return _finish(str(path), checked, matches)
    if fmt == "cab" and common.OS_NAME == "windows":
        tmp = Path(tempfile.mkdtemp(prefix="sd-lol-"))
        try:
            res = common.run(["expand", "-F:*", str(path), str(tmp)], timeout=600)
            if res is None or res.rc != 0:
                return None
            return check_directory(tmp, blocklist)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)       # purge, whether clean or not
    return None
