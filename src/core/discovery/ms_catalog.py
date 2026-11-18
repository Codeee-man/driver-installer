"""Windows driver discovery through the Microsoft Update Catalog.

Lets a Windows machine find newer drivers by hardware ID (PCI\\VEN_xxxx&DEV_xxxx) without a
SafeDriver manifest. The catalog has no public API, so this module reads the same three
pages a browser does:

  Search.aspx?q=<hardware id>        result table: title, products, classification, date, version, size
  ScopedViewInline.aspx?updateid=    details: architecture, driver provider/class, supported hardware IDs
  DownloadDialog.aspx (POST)         direct file URLs on *.download.windowsupdate.com and their digests

Trust model. Search results are untrusted text. A discovered package is installed only if
  1. it is downloaded over HTTPS from a Microsoft download host (DOWNLOAD_HOSTS), every hop;
  2. the digest the catalog published for it matches (when one is published);
  3. no .sys inside is on the LOLDrivers blocklist (core/security/loldrivers.py);
  4. the .cat inside is validly signed by Microsoft's hardware publisher (trust.MS_WHQL_SUBJECT),
     checked by the elevated helper after unpacking, and again by Windows when pnputil stages it.
The helper enforces 3 and 4 itself and ignores whatever policy the front end claims.

The page layout is Microsoft's and can change without notice; a layout change makes
discovery return nothing (CatalogError), it cannot make it install something unverified.
Verified against the live catalog from a Windows runner on 2026-11-18: search table, details
page (architecture, supported hardware IDs), download dialog (URL, SHA-1 and SHA-256), and a
full download -> digest -> LOLDrivers -> Microsoft-signature check for four real NIC/Wi-Fi IDs.
Each search sends one hardware ID of this machine to Microsoft and is written to the audit log.
"""
from __future__ import annotations

import base64
import binascii
import dataclasses
import datetime as dt
import json
import re
import sys
import time
import urllib.parse
from html.parser import HTMLParser

from .. import common, trust, verifier
from ..common import VerificationError
from ..model import Device, is_newer, parse_version

BASE = "https://www.catalog.update.microsoft.com"
DOWNLOAD_HOSTS = ("download.windowsupdate.com", "dl.delivery.mp.microsoft.com")   # these and their subdomains
MAX_PAGE_BYTES = 4 << 20
MAX_DRIVER_BYTES = 2 << 30
MAX_DEVICES = 40
REQUEST_DELAY = 0.4            # seconds between catalog requests: be a polite client
_GUID = re.compile(r"^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$")
_ROW_ID = re.compile(r"^([0-9a-fA-F-]{36})_R\d+$")
_HWID = re.compile(r"\b(?:PCI|USB|HDAUDIO|ACPI|HID|BTH|SWC|ROOT|UEFI)\\[A-Z0-9_&\\.{}\-]+", re.I)
_ARCH = {"amd64": "x86_64", "x64": "x86_64", "arm64": "aarch64", "x86": "x86"}
_FILE = re.compile(r"downloadInformation\[(\d+)\]\.files\[(\d+)\]\.(url|digest|sha256)\s*=\s*'([^']*)'")


class CatalogError(Exception):
    """The catalog could not be reached or its pages no longer look as expected."""


@dataclasses.dataclass
class CatalogEntry:
    update_id: str
    title: str
    products: str
    classification: str
    last_updated: str          # ISO date, "" if unparseable
    version: str
    size: int                  # bytes, 0 if unknown


@dataclasses.dataclass
class CatalogDetails:
    architectures: list[str]
    hardware_ids: list[str]    # upper case, as listed by the catalog
    provider: str = ""
    driver_class: str = ""
    version_date: str = ""


@dataclasses.dataclass
class CatalogFile:
    url: str
    sha1: str = ""             # hex
    sha256: str = ""           # hex


# ---------------------------------------------------------------- parsing
class _ResultTable(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.rows: list[dict] = []
        self._row = self._cell = None
        self._original_size = False

    def handle_starttag(self, tag, attrs):
        attr = dict(attrs)
        if tag == "tr":
            m = _ROW_ID.match(attr.get("id") or "")
            self._row = {"id": m.group(1).lower(), "cells": [], "size": ""} if m else None
        elif self._row is not None and tag == "td":
            self._cell = []
        elif self._row is not None and tag == "span":
            self._original_size = (attr.get("id") or "").endswith("_originalSize")

    def handle_endtag(self, tag):
        if tag == "span":
            self._original_size = False
        elif tag == "td" and self._row is not None and self._cell is not None:
            self._row["cells"].append(" ".join(t for t in self._cell if t))
            self._cell = None
        elif tag == "tr" and self._row is not None:
            self.rows.append(self._row)
            self._row = None

    def handle_data(self, data):
        if self._row is None:
            return
        if self._original_size:
            self._row["size"] = data.strip()
        elif self._cell is not None:
            self._cell.append(" ".join(data.split()))


class _Text(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self._skip += 1
        elif tag in ("div", "br", "tr", "p", "li", "td"):
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in ("script", "style"):
            self._skip = max(0, self._skip - 1)

    def handle_data(self, data):
        if not self._skip:
            self.parts.append(data)


def _iso_date(text: str) -> str:
    for fmt in ("%m/%d/%Y", "%Y-%m-%d", "%d.%m.%Y"):
        try:
            return dt.datetime.strptime(text.strip(), fmt).date().isoformat()
        except ValueError:
            continue
    return ""


def parse_search(html: str) -> list[CatalogEntry]:
    """Rows of the result table. An empty list means "no results"; a page that is neither a
    result table nor the no-results message raises CatalogError."""
    table = _ResultTable()
    table.feed(html)
    entries = []
    for row in table.rows:
        cells = row["cells"]
        if len(cells) < 7 or not _GUID.match(row["id"]):
            continue
        entries.append(CatalogEntry(row["id"], cells[1], cells[2], cells[3], _iso_date(cells[4]), cells[5],
                                    int(row["size"]) if row["size"].isdigit() else 0))
    if not entries and "did not find any results" not in html and "updateMatches" not in html:
        raise CatalogError("unexpected search page layout")
    return entries


def parse_details(html: str) -> CatalogDetails:
    text = _Text()
    text.feed(html)
    flat = re.sub(r"[ \t\r\f\v]+", " ", "".join(text.parts))

    def field(label: str) -> str:
        m = re.search(re.escape(label) + r"\s*:\s*\n?\s*([^\n]+)", flat, re.I)
        return m.group(1).strip() if m else ""

    archs = []
    for token in re.split(r"[,\s/]+", field("Architecture").lower()):
        if token in _ARCH and _ARCH[token] not in archs:
            archs.append(_ARCH[token])
    ids = []
    for hwid in _HWID.findall(flat):
        if hwid.upper() not in ids:
            ids.append(hwid.upper())
    return CatalogDetails(archs, ids, field("Driver Provider") or field("Company"), field("Driver Class"),
                          _iso_date(field("Version Date")))


def _digest_hex(value: str, length: int) -> str:
    """The dialog publishes digests as base64 (occasionally hex). Returns lower-case hex or ""."""
    value = value.strip()
    if re.fullmatch(r"[0-9a-fA-F]{%d}" % (length * 2), value):
        return value.lower()
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return ""
    return raw.hex() if len(raw) == length else ""


def parse_download_dialog(html: str) -> list[CatalogFile]:
    files: dict[tuple[str, str], CatalogFile] = {}
    for info, index, key, value in _FILE.findall(html):
        entry = files.setdefault((info, index), CatalogFile(""))
        if key == "url":
            entry.url = value
        elif key == "digest":
            entry.sha1 = _digest_hex(value, 20)
        else:
            entry.sha256 = _digest_hex(value, 32)
    return [f for f in files.values() if f.url]


def is_download_host(hostname: str) -> bool:
    hostname = (hostname or "").lower().rstrip(".")
    return any(hostname == h or hostname.endswith("." + h) for h in DOWNLOAD_HOSTS)


def normalise_download_url(url: str) -> str:
    """Catalog links are sometimes plain http; the same hosts serve https. Never download over http."""
    parts = urllib.parse.urlsplit(url)
    if not is_download_host(parts.hostname or ""):
        raise CatalogError(f"download link points at an unexpected host: {parts.hostname}")
    return urllib.parse.urlunsplit(("https", parts.netloc, parts.path, parts.query, ""))


# --------------------------------------------------------------- requests
class CatalogClient:
    """The three catalog requests. `fetch` is injectable so tests can supply canned pages."""

    def __init__(self, base: str | None = None, fetch=None, delay: float | None = None,
                 allow_loopback_http: bool = False):
        self.base = (base or BASE).rstrip("/")
        self.delay = REQUEST_DELAY if delay is None else delay
        self._last = 0.0
        self._fetch = fetch or (lambda url, data=None: verifier.http_fetch(
            url, data=data, limit=MAX_PAGE_BYTES, allow_loopback_http=allow_loopback_http,
            headers={"Content-Type": "application/x-www-form-urlencoded"} if data else None))

    def _get(self, url: str, data: bytes | None = None) -> str:
        wait = self.delay - (time.monotonic() - self._last)
        if wait > 0:
            time.sleep(wait)
        try:
            body = self._fetch(url, data)
        except VerificationError as exc:
            raise CatalogError(str(exc)) from exc
        finally:
            self._last = time.monotonic()
        return body.decode("utf-8", "replace")

    def search(self, query: str) -> list[CatalogEntry]:
        common.audit("catalog.search", query=query)
        return parse_search(self._get(f"{self.base}/Search.aspx?q={urllib.parse.quote(query, safe='')}"))

    def details(self, update_id: str) -> CatalogDetails:
        if not _GUID.match(update_id):
            raise CatalogError("malformed update id")
        return parse_details(self._get(f"{self.base}/ScopedViewInline.aspx?updateid={update_id}"))

    def files(self, update_id: str) -> list[CatalogFile]:
        if not _GUID.match(update_id):
            raise CatalogError("malformed update id")
        body = json.dumps([{"size": 0, "languages": "", "uidInfo": update_id, "updateID": update_id}],
                          separators=(",", ":"))
        html = self._get(f"{self.base}/DownloadDialog.aspx",
                         urllib.parse.urlencode({"updateIDs": body}).encode())
        files = parse_download_dialog(html)
        if not files:
            raise CatalogError("the catalog returned no download link for this update")
        return files


# -------------------------------------------------------------- selection
def query_ids(device: Device) -> list[str]:
    """Hardware IDs to search for, most specific first, in the catalog's (Windows) spelling."""
    out = []
    for hid in sorted(device.hardware_ids, key=lambda h: -h.count(":")):
        parts = hid.split(":")
        if parts[0] == "pci" and len(parts) == 5:
            query = f"PCI\\VEN_{parts[1]}&DEV_{parts[2]}&SUBSYS_{parts[4]}{parts[3]}".upper()
        elif parts[0] == "pci" and len(parts) == 3:
            query = f"PCI\\VEN_{parts[1]}&DEV_{parts[2]}".upper()
        elif parts[0] == "usb" and len(parts) == 3:
            query = f"USB\\VID_{parts[1]}&PID_{parts[2]}".upper()
        else:
            continue
        if query not in out:
            out.append(query)
    return out


def _device_windows_ids(device: Device) -> set[str]:
    return {h[4:].upper() for h in device.hardware_ids if h.startswith("raw:")} | set(query_ids(device))


# Minimum build for the release names the catalog uses in its "Products" column.
_WIN10_RELEASES = {"1507": 10240, "1511": 10586, "1607": 14393, "1703": 15063, "1709": 16299, "1803": 17134,
                   "1809": 17763, "1903": 18362, "1909": 18363, "2004": 19041, "20h2": 19042, "21h1": 19043,
                   "21h2": 19044, "22h2": 19045, "vibranium": 19041}
_WIN11_RELEASES = {"21h2": 22000, "copper": 22000, "22h2": 22621, "nickel": 22621, "23h2": 22631,
                   "24h2": 26100, "germanium": 26100, "25h2": 26200, "26h1": 28000}
_RELEASE = re.compile(r"\b(\d{4}|\d{2}h\d|vibranium|copper|nickel|germanium)\b", re.I)


def _os_ok(products: str, build: int | None) -> bool:
    """True if any product in the catalog's "Products" text covers this Windows build.

    "Windows 11 Client, version 25H2 and later" needs build 26200, so it is not offered to a
    24H2 (26100) PC, whose INF would not match. "Windows 10 ... and later" also covers Windows 11.
    Products that name no Windows 10/11 release (7, 8.1, Server-only) never match."""
    for chunk in re.split(r"(?i)(?=\bwindows )", products or ""):
        head = re.match(r"(?i)windows (10|11)\b", chunk)
        if not head:
            continue                                   # Windows 7, 8.1, Server ... products
        if build is None:
            return True
        family = head.group(1)
        if family == "11" and build < 22000:
            continue                                   # Windows 11 driver on Windows 10
        release = _RELEASE.search(chunk[head.end():])
        table = _WIN11_RELEASES if family == "11" else _WIN10_RELEASES
        if build >= (table.get(release.group(1).lower(), 0) if release else 0):
            return True
    return False


def _windows_build() -> int | None:
    getter = getattr(sys, "getwindowsversion", None)
    return getter().build if getter else None


# Details pages fetched per device: the whole first page of results. Each driver version is
# usually listed once per Windows release (often 10-15 times), so a small cap misses older
# versions that do support this device (found live: Realtek USB REV_3100 at positions 19-24).
# Details are only fetched when newer versions exist, so up-to-date devices cost one search.
MAX_DETAILS = 25


def _reject_reason(entry: CatalogEntry, device: Device, os_build: int | None) -> str:
    """Why a search result cannot be this device's update, or "" if it might be."""
    if not entry.classification.lower().startswith("driver"):
        return f"not a driver ({entry.classification or 'no classification'})"
    if not parse_version(entry.version):
        return "no usable version"
    if not _os_ok(entry.products, os_build):
        return "not for this Windows version"
    if not is_newer(entry.version, device.driver_version):
        return "not newer than the installed driver"
    return ""


def best_update(device: Device, client: CatalogClient, *, arch: str | None = None,
                os_build: int | None = None) -> dict | None:
    """The newest matching catalog driver for one device as a package dict, or None.

    Hardware IDs are tried from most to least specific (PCI\\VEN&DEV&SUBSYS, then PCI\\VEN&DEV;
    USB\\VID&PID): the next, broader query runs only when the previous one produced no usable
    driver. Every step is written to the audit log as catalog.device with the number of results
    and the reason each one was set aside, so a run that finds nothing can be explained."""
    arch = arch or common.ARCH
    mine = _device_windows_ids(device)
    queries = query_ids(device)
    steps = []
    for level, query in enumerate(queries):
        entries = client.search(query)
        step = {"query": query, "level": "full" if level == 0 and len(queries) > 1 else "base",
                "results": len(entries), "skipped": {}}
        steps.append(step)

        def skip(reason):
            step["skipped"][reason] = step["skipped"].get(reason, 0) + 1
        candidates, seen = [], set()
        for e in entries:
            reason = _reject_reason(e, device, os_build)
            if reason:
                skip(reason)
            elif e.update_id not in seen:
                seen.add(e.update_id)
                candidates.append(e)
        candidates.sort(key=lambda e: (parse_version(e.version), e.last_updated), reverse=True)
        step["candidates"] = len(candidates)
        for n, entry in enumerate(candidates):
            if n >= MAX_DETAILS:
                skip(f"not examined (only the {MAX_DETAILS} newest are checked)")
                continue
            info = client.details(entry.update_id)
            if info.architectures and arch not in info.architectures:
                skip(f"built for {'/'.join(info.architectures)}, not {arch}")
                continue
            if info.hardware_ids and not mine & set(info.hardware_ids):
                skip("this device's hardware IDs are not in the driver's supported list")
                continue
            step["chosen"] = {"update_id": entry.update_id, "version": entry.version, "title": entry.title}
            common.audit("catalog.device", device=device.name, installed=device.driver_version, steps=steps,
                         outcome=f"update {entry.version}")
            return to_package(entry, info, device, query, arch)
    outcome = "no PCI/USB hardware ID to search for" if not queries else "no newer driver that fits"
    common.audit("catalog.device", device=device.name, installed=device.driver_version, steps=steps, outcome=outcome)
    return None


def to_package(entry: CatalogEntry, info: CatalogDetails, device: Device, query: str, arch: str) -> dict:
    """Same shape as a manifest package, marked origin=ms-catalog. The download URL, size and
    SHA-256 are filled in by resolve_download() / the download step."""
    package = {
        "id": f"mscatalog.{entry.update_id}", "origin": "ms-catalog", "update_id": entry.update_id,
        "name": entry.title[:200] or device.name, "vendor": info.provider or device.vendor or "Unknown",
        "category": "driver", "version": entry.version,
        "platform": {"os": "windows", "arch": info.architectures or [arch]},
        "hardware_ids": [h for h in device.hardware_ids if not h.startswith("raw:")][:1] or ["raw:" + query.lower()],
        "matched_hardware_id": query, "id_confirmed": bool(info.hardware_ids),
        "artifact": {"url": "", "filename": f"{entry.update_id}.cab", "size": entry.size, "sha256": "",
                     "format": "cab",
                     "signature": {"type": "authenticode", "target": "catalog", "subject": trust.MS_WHQL_SUBJECT}},
        "install": {"method": "pnputil", "reboot_required": False},
        "upstream": {"source": "microsoft-update-catalog",
                     "reference_url": f"{BASE}/ScopedViewInline.aspx?updateid={entry.update_id}"},
    }
    if info.version_date or entry.last_updated:
        package["release_date"] = info.version_date or entry.last_updated
    return package


def discover(devices: list[Device], client: CatalogClient | None = None, *, limit: int = MAX_DEVICES,
             arch: str | None = None, os_build: int | None = None, progress=None) -> list[tuple[Device, dict]]:
    """Search the catalog for every device that has a PCI/USB hardware ID.

    Devices sharing an ID are searched once. One failed lookup does not stop the others; if
    the very first request fails the catalog is assumed unreachable and CatalogError is raised."""
    client = client or CatalogClient()
    os_build = os_build if os_build is not None else _windows_build()
    found, seen, searched = [], {}, 0
    searchable = [d for d in devices if query_ids(d)]
    common.audit("catalog.start", devices=len(devices), searchable=len(searchable), os_build=os_build,
                 arch=arch or common.ARCH,
                 not_searchable=len(devices) - len(searchable))      # ACPI, ROOT, SWD, VMBUS... have no catalog ID
    for device in devices:
        queries = query_ids(device)
        if not queries:
            continue
        key = (queries[0], device.driver_version)
        if key not in seen:
            if searched >= limit:
                common.audit("catalog.limit", limit=limit)
                break
            searched += 1
            if progress:
                progress(device.name)
            try:
                seen[key] = best_update(device, client, arch=arch, os_build=os_build)
            except CatalogError as exc:
                common.audit("catalog.error", device=device.name, error=str(exc))
                if searched == 1:
                    raise
                seen[key] = None
        if seen[key]:
            found.append((device, dict(seen[key])))
    common.audit("catalog.done", searched=searched, updates=len(found))
    return found


def resolve_download(package: dict, client: CatalogClient | None = None) -> CatalogFile:
    """Ask the catalog for the direct download link of a discovered package (its .cab)."""
    files = (client or CatalogClient()).files(package["update_id"])
    cabs = [f for f in files if urllib.parse.urlsplit(f.url).path.lower().endswith(".cab")]
    if not cabs:
        raise CatalogError("the catalog offers no .cab driver package for this update")
    chosen = cabs[0]
    chosen.url = normalise_download_url(chosen.url)
    return chosen
