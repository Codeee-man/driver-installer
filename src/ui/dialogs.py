"""Confirmation dialogs. These are safety prompts, not notifications: each one appears only
in answer to the user's own action, and Cancel is always the default button.

ConfirmDialog shows the same text a QMessageBox would, but never grows past the screen:
indented blocks of the text (the driver list, the per-driver verification notes) go into their
own framed, read-only scroll boxes, the details sit behind "Show Details...", and the buttons
are pinned below everything, outside any scrolling."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QFontMetrics, QGuiApplication
from PySide6.QtWidgets import (QDialog, QDialogButtonBox, QHBoxLayout, QLabel, QPlainTextEdit, QPushButton, QSizePolicy,
                               QVBoxLayout)

from . import verification as vf

MAX_HEIGHT = 580                 # the dialog never exceeds this, nor 75 % of the screen
LIST_MAX = 160                   # px: the driver list (old -> new)
NOTES_MAX = 240                  # px: the verification notes / details box
INDENT = "  "


def blocks(text: str) -> list[tuple[str, str]]:
    """Split dialog text into ("label", line) and ("box", lines) parts: lines starting with two
    spaces form a box (indent removed), everything else is a label. Blank lines separate labels."""
    parts: list[tuple[str, list[str]]] = []
    for line in text.split("\n"):
        kind = "box" if line.startswith(INDENT) else ("gap" if not line.strip() else "label")
        if kind == "box" and parts and parts[-1][0] == "box":
            parts[-1][1].append(line[len(INDENT):])
        elif kind == "label":
            parts.append(("label", [line]))
        elif kind == "box":
            parts.append(("box", [line[len(INDENT):]]))
    return [(kind, "\n".join(lines)) for kind, lines in parts]


class ConfirmDialog(QDialog):
    def __init__(self, parent, title: str, text: str, details: str, accept_label: str):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setObjectName("confirm")
        self.setModal(True)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 16)
        layout.setSpacing(8)
        self.labels: list[QLabel] = []
        self.boxes: list[QPlainTextEdit] = []
        for n, (kind, body) in enumerate(blocks(text)):
            if kind == "label":
                label = QLabel(body, objectName="confirmTitle" if n == 0 else "confirmText", wordWrap=True)
                label.setTextInteractionFlags(Qt.TextSelectableByMouse)
                self.labels.append(label)
                layout.addWidget(label)
            else:
                # First box: the driver list; any later one: verification notes.
                box = self._box(body, LIST_MAX if not self.boxes else NOTES_MAX)
                box.setObjectName("confirmList" if not self.boxes else "confirmNotes")
                self.boxes.append(box)
                layout.addWidget(box, 1)
        self.details = self._box(details, NOTES_MAX) if details else None
        if self.details:
            self.details.setObjectName("confirmNotes")
            self.details.hide()
            layout.addWidget(self.details, 1)
        # Pinned, never inside a scroll box: details toggle on the left, Install / Cancel on the right.
        row = QHBoxLayout()
        row.setSpacing(8)
        self.details_button = None
        if self.details:
            self.details_button = QPushButton("Show Details...", objectName="ghost", checkable=True)
            self.details_button.setAutoDefault(False)
            self.details_button.toggled.connect(self._toggle_details)
            row.addWidget(self.details_button)
        row.addStretch(1)
        self.buttons = QDialogButtonBox(self)
        self.accept_button = QPushButton(accept_label, objectName="primary")   # named before it is styled
        self.accept_button.setAutoDefault(False)
        self.buttons.addButton(self.accept_button, QDialogButtonBox.AcceptRole)
        self.cancel_button = self.buttons.addButton(QDialogButtonBox.Cancel)
        self.cancel_button.setDefault(True)
        self.cancel_button.setFocus()
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        row.addWidget(self.buttons)
        layout.addLayout(row, 0)
        self._fit()

    @staticmethod
    def _box(body: str, max_height: int) -> QPlainTextEdit:
        box = QPlainTextEdit(body, readOnly=True)
        box.setLineWrapMode(QPlainTextEdit.WidgetWidth)
        box.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        lines = max(body.count("\n") + 1, 1)
        wanted = QFontMetrics(box.font()).lineSpacing() * lines + 16
        box.setMinimumHeight(min(wanted, 56))
        box.setMaximumHeight(min(wanted, max_height))
        box.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        return box

    def limit(self) -> int:
        screen = (self.parentWidget().screen() if self.parentWidget() else None) or QGuiApplication.primaryScreen()
        return min(MAX_HEIGHT, int(screen.availableGeometry().height() * 0.75))

    def _fit(self) -> None:
        self.setMaximumHeight(self.limit())
        self.setMinimumWidth(460)
        self.adjustSize()
        self.resize(max(self.width(), 520), min(self.sizeHint().height(), self.limit()))

    def _toggle_details(self, shown: bool) -> None:
        self.details.setVisible(shown)
        self.details_button.setText("Hide Details..." if shown else "Show Details...")
        self._fit()


def ask(parent, title: str, text: str, details: str, accept_label: str) -> bool:
    dialog = ConfirmDialog(parent, title, text, details, accept_label)
    return dialog.exec() == QDialog.Accepted


def install_confirmation(updates, plan: list[str]) -> tuple[str, str, str, str]:
    """(title, text, details, accept label) for the "Download and Install" confirmation.
    Every update and every partial note is listed: the dialog scrolls them instead of cutting."""
    partial = [u for u in updates if vf.level(u) == vf.PARTIAL]
    lines = [f"Install {len(updates)} driver update(s)?", ""]
    lines += [f"{INDENT}{u.device.name}: {u.installed} → {u.available}" for u in updates]
    if partial:
        lines += ["", f"{len(partial)} of them are only partially verified:"]
        lines += [f"{INDENT}{u.device.name}: {vf.missing_summary(u)}" for u in partial]
    lines += ["", "A restore point is created first. You will be asked for administrator rights."]
    details = "\n\n".join(vf.explain(u) for u in updates) + "\n\nPlan:\n" + "\n".join(plan)
    return "Download and Install", "\n".join(lines), details, "Install"
