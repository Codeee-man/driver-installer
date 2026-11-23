"""ChecksPopover: the itemised verification result behind the (?) of a Partial badge.

A small frameless panel that closes on Escape or a click elsewhere. Each check is one line
with a coloured symbol (✓ passed, ✗ failed, ○ skipped, – not applicable) and its reason.
"""
from __future__ import annotations

from PySide6.QtCore import QPoint, Qt
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import QFrame, QGridLayout, QLabel, QVBoxLayout

from core.model import AT_INSTALL, FAILED, NOT_APPLICABLE, PASSED, SKIPPED
from . import theme
from . import verification as vf

WIDTH = 440


def _state_color(state: str) -> str:
    return {PASSED: theme.GREEN, FAILED: theme.RED, SKIPPED: theme.AMBER, NOT_APPLICABLE: theme.MUTED_DIM,
            AT_INSTALL: theme.ACCENT}[state]


def _level_color(level: str) -> str:
    return {vf.FULL: theme.GREEN, vf.PARTIAL: theme.AMBER, vf.NONE: theme.RED}.get(level, theme.MUTED)


class ChecksPopover(QFrame):
    def __init__(self, parent, update):
        super().__init__(parent, Qt.Popup | Qt.FramelessWindowHint)
        self.setObjectName("popover")
        self.setAttribute(Qt.WA_DeleteOnClose)
        self.setFixedWidth(WIDTH)
        self.update_ref = update
        lvl = vf.level(update)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(14, 12, 14, 12)
        outer.setSpacing(10)
        title = QLabel(theme.badge_text(f"Verification: {lvl}"))
        title.setObjectName("popoverTitle")
        title.setStyleSheet(f"color: {_level_color(lvl)};")
        outer.addWidget(title)
        failed = [c for c in update.checks if c.state == FAILED]
        if failed:
            hint = QLabel("Failed: " + "; ".join(f"{c.label}: {c.reason}" for c in failed))
            hint.setObjectName("checkReason")
            hint.setWordWrap(True)
            hint.setTextInteractionFlags(Qt.TextSelectableByMouse)
            outer.addWidget(hint)
        elif vf.missing(update):
            hint = QLabel("Not done: " + ", ".join(c.label for c in vf.missing(update)))
            hint.setObjectName("checkReason")
            hint.setWordWrap(True)
            outer.addWidget(hint)
        grid = QGridLayout()
        grid.setHorizontalSpacing(10)
        grid.setVerticalSpacing(2)
        row = 0
        for check in update.checks:
            symbol = QLabel(vf.SYMBOL[check.state])
            symbol.setStyleSheet(f"color: {_state_color(check.state)}; font-weight: 700;")
            symbol.setAlignment(Qt.AlignTop | Qt.AlignHCenter)
            label = QLabel(f"{check.label}  ·  {vf.STATE_TEXT[check.state]}")
            label.setObjectName("checkLabel")
            if check.state != PASSED:
                label.setStyleSheet(f"color: {_state_color(check.state)};")
            grid.addWidget(symbol, row, 0)
            grid.addWidget(label, row, 1)
            row += 1
            if check.reason:
                reason = QLabel(check.reason)
                reason.setObjectName("checkReason")
                reason.setWordWrap(True)
                reason.setTextInteractionFlags(Qt.TextSelectableByMouse)
                grid.addWidget(reason, row, 1)
                row += 1
            grid.setRowMinimumHeight(row, 6)
            row += 1
        grid.setColumnStretch(1, 1)
        outer.addLayout(grid)
        self.setAccessibleName("Verification details")
        self.setAccessibleDescription(vf.explain(update))

    def text(self) -> str:
        return vf.explain(self.update_ref)

    def show_at(self, point: QPoint) -> None:
        self.adjustSize()
        screen = QGuiApplication.screenAt(point) or QGuiApplication.primaryScreen()
        if screen is not None:
            area = screen.availableGeometry()
            x = min(max(point.x(), area.left() + 4), area.right() - self.width() - 4)
            y = point.y() if point.y() + self.height() < area.bottom() else point.y() - self.height() - 30
            point = QPoint(x, max(y, area.top() + 4))
        self.move(point)
        self.show()

    def keyPressEvent(self, event):
        if event.key() == Qt.Key_Escape:
            self.close()
            return
        super().keyPressEvent(event)
