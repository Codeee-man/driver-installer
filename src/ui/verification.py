"""Verification level and the texts shown for it. Pure Python, no Qt.

Level rules (applied to update.checks, see core/model.py):
  None     any check failed, or the update could not be verified at all
  Partial  nothing failed, but at least one applicable check could not be done ("skipped")
  Full     every check passed or does not apply ("not applicable"): for example a Microsoft
           Update Catalog driver needs no Ed25519 manifest because Microsoft's driver signature
           is required instead, and fwupd / the package manager verify their own downloads.
  Pending  still downloading and checking
"""
from __future__ import annotations

from core.model import FAILED, NOT_APPLICABLE, PASSED, SKIPPED

FULL, PARTIAL, NONE, PENDING = "Full", "Partial", "None", "Pending"
KIND = {FULL: "full", PARTIAL: "partial", NONE: "none", PENDING: "busy"}
SYMBOL = {PASSED: "✓", FAILED: "✗", SKIPPED: "○", NOT_APPLICABLE: "–"}
STATE_TEXT = {PASSED: "passed", FAILED: "FAILED", SKIPPED: "skipped", NOT_APPLICABLE: "not applicable"}
RANK = {FULL: 0, PARTIAL: 1, PENDING: 2, NONE: 3}


def level(update) -> str:
    """Full / Partial / None / Pending for an update; "" for a device without an update."""
    if update is None:
        return ""
    states = [c.state for c in update.checks]
    if update.status == "failed" or FAILED in states:
        return NONE
    if update.status == "pending" or not states:
        return PENDING
    if SKIPPED in states:
        return PARTIAL
    return FULL


def missing(update) -> list:
    """Checks that apply but were not done, or failed."""
    return [c for c in update.checks if c.state in (SKIPPED, FAILED)]


def explain(update) -> str:
    """Multi-line plain text: the level and every check with its reason (tooltips, dialogs)."""
    lines = [f"Verification: {level(update)}"]
    for c in update.checks:
        lines.append(f"{SYMBOL[c.state]} {c.label}: {STATE_TEXT[c.state]}")
        if c.reason:
            lines.append(f"    {c.reason}")
    return "\n".join(lines)


def missing_summary(update) -> str:
    """One line naming what is missing, e.g. "LOLDrivers BYOVD check skipped (database offline ...)"."""
    return "; ".join(f"{c.label} {STATE_TEXT[c.state]}" + (f" ({c.reason})" if c.reason else "")
                     for c in missing(update))


OUTCOMES = {
    "installed": ("Installed", "ok"),
    "reboot-required": ("Restart required", "warn"),
    "no-op": ("Up to date", "uptodate"),
    "failed": ("Failed", "alert"),
    "refused": ("Blocked", "alert"),
}


LOOKUP = {"queued": ("Queued", "busy"), "scanning": ("Scanning…", "busy"), "not-checked": ("Not checked", "warn")}


def row_status(update, outcome: dict | None = None, phase: str = "done") -> tuple[str, str]:
    """(text, badge kind) for the Status column. phase: the row's lookup state (ui.models)."""
    if outcome:
        return OUTCOMES.get(outcome.get("status"), ("Failed", "alert"))
    if phase == "not-checked":
        return LOOKUP[phase]
    if update is None:
        return LOOKUP.get(phase, ("Up to date", "uptodate"))
    if update.status == "pending" or (not update.checks and update.status != "failed"):
        return "Checking…", "busy"
    return "To update", "accent"
