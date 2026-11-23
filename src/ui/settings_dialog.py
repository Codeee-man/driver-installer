"""[ SETTINGS ]: accent colour, font, and the startup update check.

A compact, non-modal-feeling dialog in the Matrix style. Every click applies at once (the
window restyles itself through `changed`) and is saved to ui.json by the window; there is no
OK / Cancel to remember.
"""
from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QIcon, QPixmap
from PySide6.QtWidgets import (QButtonGroup, QCheckBox, QDialog, QFrame, QGridLayout, QHBoxLayout, QLabel,
                               QPushButton, QVBoxLayout)

from . import theme


def swatch(hex_value: str, size: int = 12) -> QIcon:
    """A flat square of the accent colour with a 1 px dark edge."""
    pix = QPixmap(size, size)
    pix.fill(QColor(theme.BG))
    inner = QPixmap(size - 2, size - 2)
    inner.fill(QColor(hex_value))
    from PySide6.QtGui import QPainter
    painter = QPainter(pix)
    painter.drawPixmap(1, 1, inner)
    painter.end()
    return QIcon(pix)


class SettingsDialog(QDialog):
    """Emits changed({"accent": ..., "font": ..., "check_updates": ...}) on every change."""
    changed = Signal(dict)

    def __init__(self, parent, values: dict):
        super().__init__(parent)
        self.setObjectName("settings")
        self.setWindowTitle("Settings")
        self.values = dict(values)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(10)
        layout.addWidget(QLabel("[ SETTINGS ]", objectName="settingsTitle"))
        layout.addWidget(QFrame(objectName="rule"))

        layout.addWidget(QLabel("ACCENT COLOR", objectName="settingsSection"))
        self.accents = QButtonGroup(self)
        grid = QGridLayout()
        grid.setSpacing(6)
        for i, (key, (label, hex_value)) in enumerate(theme.ACCENTS.items()):
            button = self._preset(label.upper(), key, self.accents, values.get("accent") == key)
            button.setIcon(swatch(hex_value))
            button.setToolTip(f"{label} ({hex_value})")
            grid.addWidget(button, i // 3, i % 3)
        layout.addLayout(grid)

        layout.addWidget(QLabel("FONT", objectName="settingsSection"))
        self.fonts = QButtonGroup(self)
        row = QHBoxLayout()
        row.setSpacing(6)
        hints = {"vt323": "VT323, the bundled retro terminal font",
                 "mono": "Consolas / JetBrains Mono / the system monospace font",
                 "sans": "Segoe UI / the system sans-serif font"}
        for key, preset in theme.FONTS.items():
            button = self._preset(preset.label.upper(), key, self.fonts, values.get("font") == key)
            button.setToolTip(hints.get(key, preset.label))
            row.addWidget(button)
        layout.addLayout(row)

        layout.addWidget(QFrame(objectName="rule"))
        self.check_updates = QCheckBox("Check for updates on startup")
        self.check_updates.setChecked(bool(values.get("check_updates", True)))
        self.check_updates.setToolTip("Ask GitHub once per start whether a newer release exists; nothing is downloaded")
        layout.addWidget(self.check_updates)

        close = QPushButton("[ CLOSE ]", objectName="headerButton")
        close.setCursor(Qt.PointingHandCursor)
        close.clicked.connect(self.accept)
        bottom = QHBoxLayout()
        bottom.addStretch(1)
        bottom.addWidget(close)
        layout.addLayout(bottom)

        self.accents.idClicked.connect(lambda _: self._set("accent", self.accents.checkedButton().property("key")))
        self.fonts.idClicked.connect(lambda _: self._set("font", self.fonts.checkedButton().property("key")))
        self.check_updates.toggled.connect(lambda on: self._set("check_updates", bool(on)))
        self.setFixedWidth(460)

    def _preset(self, text: str, key: str, group: QButtonGroup, checked: bool) -> QPushButton:
        button = QPushButton(text, objectName="preset", checkable=True, checked=checked)
        button.setProperty("key", key)
        button.setCursor(Qt.PointingHandCursor)
        group.addButton(button)
        return button

    def button(self, key: str) -> QPushButton:
        """The preset button for an accent or font id (tests, keyboard users)."""
        for group in (self.accents, self.fonts):
            for b in group.buttons():
                if b.property("key") == key:
                    return b
        raise KeyError(key)

    def _set(self, key: str, value) -> None:
        if self.values.get(key) == value:
            return
        self.values[key] = value
        self.changed.emit({key: value})
