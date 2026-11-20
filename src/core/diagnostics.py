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
                  "verify.", "signature.", "net.", "exec", "plan", "restore.", "install.", "helper.", "elevation.",
                  "apply.", "elevated.")
ELEVATED = "elevated."          # events the administrator run recorded, replayed by engine.forward_helper_log


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
    if event == "helper.refused":
        return [f"REFUSED {data.get('name') or data.get('item')}", f"  {data.get('reason')}"]
    if event == "helper.done":
        return [f"elevated run finished: {data.get('status')}" + (f" ({data.get('detail')})" if data.get("detail") else "")] + \
               [f"  {line}" for line in data.get("items") or []]
    if event == "helper.wua_acquired":
        return [f"Windows Update handed over {data.get('name')}: {data.get('files')} file(s), "
                f"INF {', '.join(data.get('infs') or []) or 'none'}"]
    if event == "helper.crashed":
        return [f"elevated run stopped with an internal error: {data.get('error')}"]
    if event == "verify.failed":
        step = data.get("step")
        return [f"{data.get('update')} ({data.get('source')}): verification FAILED"
                + (f" at {step}" if step else ""), f"  {data.get('reason')}"]
    if event == "verify.channel_trust":
        return [f"{data.get('update')}: Partial, trusted through the Windows Update channel until the installer "
                f"downloads it", f"  catalog: {data.get('catalog')}", f"  Windows Update Agent: {data.get('wua')}"]
    if event == "catalog.redirect":
        return [f"download dialog for {data.get('update')} answered {data.get('code')} -> {data.get('location')}"]
    if event == "catalog.download_unavailable":
        return [f"no catalog download for {data.get('update')}: {data.get('reason')}"]
    if event == "wua.fetch.failed":
        return [f"Windows Update Agent could not hand over {data.get('update')} ({data.get('stage')} step, "
                f"{data.get('hresult') or 'no HRESULT'}): {data.get('error')}"]
    if event == "wua.fetch.done":
        return [f"Windows Update Agent handed over {data.get('file')} ({data.get('size')} bytes"
                + (", already downloaded by Windows" if data.get("already_downloaded") else "") + ")"]
    return [json.dumps(data, default=str, ensure_ascii=False)[:400]]


def format_record(rec: dict, with_time: bool = True) -> str:
    event = rec.get("event", "")
    if event.startswith(ELEVATED):
        inner = {**rec, "event": event[len(ELEVATED):],
                 "data": {k: v for k, v in (rec.get("data") or {}).items() if k != "helper_ts"}}
        head, *rest = describe(inner)
        head = "[admin] " + head
        ts = str((rec.get("data") or {}).get("helper_ts") or rec.get("ts", ""))
        rec = {**rec, "ts": ts, "event": inner["event"]}
    else:
        head, *rest = describe(rec)
    prefix = f"{rec.get('ts', '')[11:19]}  " if with_time else ""
    lines = [f"{prefix}{rec.get('event', ''):<22} {head}"]
    pad = " " * (len(prefix) + 23)
    lines += [pad + line for line in rest]
    return "\n".join(lines)


def wants(event: str) -> bool:
    return event.startswith(DEBUG_PREFIXES)
