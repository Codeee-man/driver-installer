"""Readable one-line descriptions of audit records, for `--debug` and the GUI's LOG drawer.

Discovery writes counts at every step (devices scanned, devices with a searchable hardware ID,
queries sent, results returned, and the reason each result was set aside). This module turns
those records into lines a person can read, so a run that finds nothing explains itself:

    catalog.device  Realtek PCIe GbE (installed 10.50.511.2021): no newer driver that fits
                    PCI\\VEN_10EC&DEV_8168&SUBSYS_86771043 (full): 0 results
                    PCI\\VEN_10EC&DEV_8168 (base): 25 results, 9 candidates; skipped: 16 not for this ...
"""
from __future__ import annotations

import json

# Events shown by --debug (prefix match). Everything is still in the audit log.
DEBUG_PREFIXES = ("scan.", "wmi.", "catalog.", "wua.", "discovery.", "drivers.", "fwupd.", "blocklist.",
                  "verify.", "signature.", "net.", "exec", "plan", "restore.", "install.", "helper.", "elevation.")


def _skips(skipped: dict) -> str:
    return "; ".join(f"{n} {reason}" for reason, n in sorted(skipped.items(), key=lambda kv: -kv[1]))


def describe(rec: dict) -> list[str]:
    """Lines for one audit record: a headline, plus indented detail lines where useful."""
    event, data = rec.get("event", ""), rec.get("data") or {}
    if event == "catalog.device":
        lines = [f"{data.get('device')} (installed {data.get('installed') or 'unknown'}): {data.get('outcome')}"]
        for step in data.get("steps") or []:
            line = f"  {step.get('query')} ({step.get('level')}): {step.get('results')} results"
            if "candidates" in step:
                line += f", {step['candidates']} candidate(s)"
            if step.get("skipped"):
                line += f"; skipped: {_skips(step['skipped'])}"
            if step.get("chosen"):
                line += f"; chose {step['chosen']['version']} ({step['chosen']['update_id']})"
            lines.append(line)
        return lines
    if event == "catalog.start":
        return [f"{data.get('devices')} devices scanned, {data.get('searchable')} with a PCI/USB hardware ID to search "
                f"for ({data.get('not_searchable')} without one); Windows build {data.get('os_build')}, {data.get('arch')}"]
    if event == "catalog.done":
        return [f"catalog: {data.get('searched')} device(s) searched, {data.get('updates')} update(s)"]
    if event == "wua.done":
        lines = [f"Windows Update: search {data.get('result')}, {data.get('offered')} driver(s) offered, "
                 f"{data.get('matched')} matched to a scanned device"]
        lines += [f"  skipped {s.get('title')!r}: {s.get('reason')}" for s in data.get("skipped") or []]
        lines += [f"  note: {n}" for n in data.get("notes") or []]
        return lines
    if event == "scan.windows.done":
        return [f"WMI: {data.get('entities')} PnP entities, {data.get('devices')} devices with a driver or a problem"]
    if event == "discovery.windows":
        return [f"discovery: Windows Update {data.get('windows_update')}, catalog {data.get('catalog')}, "
                f"{data.get('chosen')} update(s) after taking the newest per device"]
    return [json.dumps(data, default=str, ensure_ascii=False)[:400]]


def format_record(rec: dict, with_time: bool = True) -> str:
    head, *rest = describe(rec)
    prefix = f"{rec.get('ts', '')[11:19]}  " if with_time else ""
    lines = [f"{prefix}{rec.get('event', ''):<22} {head}"]
    pad = " " * (len(prefix) + 23)
    lines += [pad + line for line in rest]
    return "\n".join(lines)


def wants(event: str) -> bool:
    return event.startswith(DEBUG_PREFIXES)
