"""Confirmation dialogs. These are safety prompts, not notifications: each one appears only
in answer to the user's own action, and Cancel is always the default button."""
from __future__ import annotations

from PySide6.QtWidgets import QMessageBox

from . import verification as vf


def ask(parent, title: str, text: str, details: str, accept_label: str) -> bool:
    box = QMessageBox(parent)
    box.setWindowTitle(title)
    box.setIcon(QMessageBox.NoIcon)
    box.setText(text)
    if details:
        box.setDetailedText(details)
    accept = box.addButton(accept_label, QMessageBox.AcceptRole)
    accept.setObjectName("primary")
    cancel = box.addButton(QMessageBox.Cancel)
    box.setDefaultButton(cancel)
    box.setEscapeButton(cancel)
    box.exec()
    return box.clickedButton() is accept


def install_confirmation(updates, plan: list[str]) -> tuple[str, str, str, str]:
    """(title, text, details, accept label) for the "Download and Install" confirmation."""
    partial = [u for u in updates if vf.level(u) == vf.PARTIAL]
    lines = [f"Install {len(updates)} driver update(s)?", ""]
    lines += [f"  {u.device.name}: {u.installed} → {u.available}" for u in updates[:8]]
    if len(updates) > 8:
        lines.append(f"  … and {len(updates) - 8} more")
    if partial:
        lines += ["", f"{len(partial)} of them are only partially verified:"]
        lines += [f"  {u.device.name}: {vf.missing_summary(u)}" for u in partial[:5]]
    lines += ["", "A restore point is created first. You will be asked for administrator rights."]
    details = "\n\n".join(vf.explain(u) for u in updates) + "\n\nPlan:\n" + "\n".join(plan)
    return "Download and Install", "\n".join(lines), details, "Install"
