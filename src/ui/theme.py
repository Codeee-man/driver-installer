"""Colour tokens, fonts and the stylesheet: a dark "Matrix terminal" look.

Pitch-black surfaces, neon green for primary text and actions, forest green for secondary
text, dark cyber green for every line. Amber and red are reserved for warnings and alerts.
No gradients; corners are sharp (3 px at most).
"""
from __future__ import annotations

BG = "#050505"              # window
SURFACE = "#0D0D0D"         # table, panels
SURFACE_HOVER = "#0A1A0F"
SURFACE_SELECTED = "#0F2617"
TEXT = "#00FF41"            # primary text
ACCENT = "#00FF66"          # primary action, "To update", "Full"
MUTED = "#00A843"           # secondary text
MUTED_DIM = "#008033"       # tertiary text, headers
BORDER = "#1A3320"
BORDER_DIM = "#0F2617"
DISABLED = "#2E5A3A"
AMBER = "#FFCC00"
AMBER_BORDER = "#5C4A00"
RED = "#FF3333"
RED_BORDER = "#5C1414"
SLATE = "#4A6B53"           # "Up to date", devices without updates

# badge kind -> (text colour, border colour, fill alpha 0-255, glow)
BADGES = {
    "full": (ACCENT, ACCENT, 26, True),
    "partial": (AMBER, AMBER_BORDER, 18, False),
    "none": (RED, RED_BORDER, 18, False),
    "accent": (ACCENT, "#00994D", 0, False),       # "To update"
    "uptodate": (SLATE, "#24392A", 0, False),
    "busy": (MUTED_DIM, BORDER, 0, False),          # "Checking"
    "ok": (ACCENT, "#00994D", 18, False),           # "Installed"
    "warn": (AMBER, AMBER_BORDER, 0, False),        # "Restart required"
    "alert": (RED, RED_BORDER, 0, False),           # "Failed"
}

MONO_FAMILIES = ["JetBrains Mono", "Fira Code", "Cascadia Mono", "Consolas", "DejaVu Sans Mono",
                 "Liberation Mono", "Menlo", "Courier New"]
_mono_family: str | None = None


def mono_family() -> str:
    """First installed monospace family from MONO_FAMILIES, else the system fixed font."""
    global _mono_family
    if _mono_family is None:
        from PySide6.QtGui import QFontDatabase
        installed = set(QFontDatabase.families())
        _mono_family = next((f for f in MONO_FAMILIES if f in installed),
                            QFontDatabase.systemFont(QFontDatabase.FixedFont).family())
    return _mono_family


def mono_font(point_size: float = 10, bold: bool = False, spacing: float = 0.0):
    from PySide6.QtGui import QFont
    font = QFont(mono_family())
    font.setStyleHint(QFont.Monospace)
    font.setPointSizeF(point_size)
    font.setBold(bold)
    if spacing:
        font.setLetterSpacing(QFont.AbsoluteSpacing, spacing)
    return font


def stylesheet() -> str:
    mono = mono_family()
    return f"""
* {{ font-family: '{mono}'; font-size: 10pt; color: {TEXT}; }}
QMainWindow, QWidget#root, QDialog, QMessageBox {{ background: {BG}; }}
QLabel {{ background: transparent; }}

QLabel#title {{ font-size: 17pt; font-weight: 700; color: {ACCENT}; letter-spacing: 2px; }}
QFrame#rule {{ background: {BORDER}; max-height: 1px; min-height: 1px; border: none; }}

QLabel#statusline {{ color: {MUTED}; font-size: 9pt; }}
QLabel#statusline[kind="error"] {{ color: {RED}; }}
QLabel#statusline[kind="warn"] {{ color: {AMBER}; }}
QLabel#statusline[kind="ok"] {{ color: {ACCENT}; }}

QTableView {{ background: {SURFACE}; border: 1px solid {BORDER}; border-radius: 3px; outline: 0;
             gridline-color: transparent; selection-background-color: {SURFACE_SELECTED}; }}
QHeaderView {{ background: {SURFACE}; border: none; }}
QHeaderView::section {{ background: {SURFACE}; color: {MUTED_DIM}; border: none;
                        border-bottom: 1px solid {BORDER}; padding: 7px 12px; font-size: 8pt; font-weight: 700; }}

QPushButton {{ background: {SURFACE}; color: {MUTED}; border: 1px solid {BORDER}; border-radius: 3px;
              padding: 7px 16px; }}
QPushButton:hover {{ color: {ACCENT}; border-color: {ACCENT}; }}
QPushButton:pressed {{ background: {SURFACE_SELECTED}; }}
QPushButton:disabled {{ color: {DISABLED}; border-color: {BORDER_DIM}; }}
QPushButton:focus {{ border-color: {MUTED}; }}
QPushButton#primary {{ background: {ACCENT}; color: {BG}; border: 1px solid {ACCENT}; font-weight: 700;
                      padding: 9px 22px; letter-spacing: 1px; }}
QPushButton#primary:hover {{ background: {TEXT}; border-color: {TEXT}; }}
QPushButton#primary:focus {{ border: 1px solid #CCFFDD; }}
QPushButton#primary:disabled {{ background: {BORDER_DIM}; color: {DISABLED}; border-color: {BORDER}; }}
QPushButton#ghost {{ background: transparent; border: 1px solid transparent; color: {MUTED_DIM};
                    padding: 4px 8px; font-size: 9pt; }}
QPushButton#ghost:hover, QPushButton#ghost:checked {{ color: {ACCENT}; border-color: {BORDER}; }}
QPushButton#ghost:disabled {{ color: {BORDER}; }}

QCheckBox {{ color: {MUTED}; spacing: 8px; }}
QCheckBox:hover {{ color: {ACCENT}; }}
QCheckBox:disabled {{ color: {DISABLED}; }}
QCheckBox::indicator {{ width: 13px; height: 13px; border: 1px solid {MUTED}; border-radius: 2px;
                       background: {BG}; }}
QCheckBox::indicator:hover {{ border-color: {ACCENT}; }}
QCheckBox::indicator:checked {{ background: {ACCENT}; border-color: {ACCENT}; }}
QCheckBox::indicator:indeterminate {{ background: {MUTED_DIM}; border-color: {MUTED}; }}
QCheckBox::indicator:disabled {{ border-color: {BORDER}; background: {BG}; }}

QPlainTextEdit#log {{ background: {BG}; border: 1px solid {BORDER}; border-radius: 3px; color: {MUTED_DIM};
                     font-size: 8pt; selection-background-color: {SURFACE_SELECTED}; }}

QFrame#popover {{ background: {SURFACE}; border: 1px solid {BORDER}; border-radius: 3px; }}
QLabel#popoverTitle {{ font-weight: 700; font-size: 9pt; }}
QLabel#checkLabel {{ color: {TEXT}; font-weight: 700; font-size: 9pt; }}
QLabel#checkReason {{ color: {MUTED}; font-size: 8pt; }}

QToolTip {{ background: {SURFACE}; color: {TEXT}; border: 1px solid {BORDER}; padding: 6px;
           font-family: '{mono}'; font-size: 9pt; }}
QMessageBox QLabel {{ color: {TEXT}; }}
QMessageBox QTextEdit {{ background: {SURFACE}; color: {MUTED}; border: 1px solid {BORDER}; }}

QScrollBar:vertical {{ background: {SURFACE}; width: 8px; margin: 0; }}
QScrollBar::handle:vertical {{ background: {BORDER}; min-height: 24px; border-radius: 3px; }}
QScrollBar::handle:vertical:hover {{ background: {MUTED_DIM}; }}
QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; width: 0; }}
QScrollBar::add-page, QScrollBar::sub-page {{ background: none; }}
"""
