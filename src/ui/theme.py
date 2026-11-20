"""Themes: "Matrix" (black, neon green, pixel terminal font) and "Clean" (Metallic Monochrome:
obsidian surfaces, brushed-silver borders and a platinum primary button, system sans-serif).

The current theme is process-wide. Colour tokens are read as module attributes
(`theme.ACCENT`, `theme.BG`, ...) and always resolve against the current theme, so painted
cells pick up a theme change on their next repaint; the window re-applies `stylesheet()`.

Fonts
  Matrix  bundled VT323 (SIL OFL, assets/fonts/) registered at start-up, then
          Fixedsys Excelsior, PxPlus IBM VGA8, Terminus, Courier New, Consolas, system mono.
  Clean   Segoe UI, Inter, Roboto, then the platform's UI font.
"""
from __future__ import annotations

import dataclasses
from pathlib import Path

FONT_DIR = Path(__file__).resolve().parent / "assets" / "fonts"
MATRIX, CLEAN = "matrix", "clean"
NAMES = (MATRIX, CLEAN)
DEFAULT = MATRIX

# Pixel fonts draw much smaller than ordinary fonts at the same point size.
FONT_SCALE = {"VT323": 1.5, "Press Start 2P": 0.72}


@dataclasses.dataclass(frozen=True)
class Theme:
    name: str
    label: str                          # shown on the theme toggle
    colors: dict                        # token -> "#rrggbb"
    badges: dict                        # kind -> (text, border, fill alpha 0-255, glow[, fill, icon])
                                        #   fill: explicit fill colour instead of text colour + alpha
                                        #   icon: "check" draws a tick before the text
    fonts: tuple                        # preferred families, best first
    mono_fonts: tuple
    radius: int                         # buttons, table, panels
    badge_radius: int
    uppercase: bool                     # badge and header text in capitals
    letter_spacing: float               # badges and headers
    title_pt: float
    title_spacing: int                  # px
    row_height: int
    header_labels: dict                 # button -> label
    panel_radius: int = 3               # table and log drawer
    badge_height: int = 20              # pills; with badge_radius = height / 2 they are full pills


_MATRIX_COLORS = {
    "BG": "#050505", "SURFACE": "#0D0D0D", "SURFACE_HOVER": "#0A1A0F", "SURFACE_SELECTED": "#0F2617",
    "TEXT": "#00FF41", "ACCENT": "#00FF66", "ON_ACCENT": "#050505", "ACCENT_HOVER": "#00FF41",
    "GREEN": "#00FF66", "MUTED": "#00A843", "MUTED_DIM": "#008033", "BORDER": "#1A3320", "BORDER_DIM": "#0F2617",
    "FOCUS": "#CCFFDD", "DISABLED": "#2E5A3A", "AMBER": "#FFCC00", "AMBER_BORDER": "#5C4A00",
    "RED": "#FF3333", "RED_BORDER": "#5C1414", "SLATE": "#4A6B53", "SLATE_DIM": "#36503D",
}
MATRIX_THEME = Theme(
    name=MATRIX, label="[ MATRIX ]", colors=_MATRIX_COLORS,
    badges={
        "full": ("#00FF66", "#00FF66", 26, True),
        "partial": ("#FFCC00", "#5C4A00", 18, False),
        "none": ("#FF3333", "#5C1414", 18, False),
        "accent": ("#00FF66", "#00994D", 0, False),     # "To update"
        "uptodate": ("#4A6B53", "#24392A", 0, False),
        "busy": ("#008033", "#1A3320", 0, False),       # "Checking"
        "ok": ("#00FF66", "#00994D", 18, False),        # "Installed"
        "warn": ("#FFCC00", "#5C4A00", 0, False),       # "Restart required"
        "alert": ("#FF3333", "#5C1414", 0, False),      # "Failed"
    },
    fonts=("VT323", "Fixedsys Excelsior", "PxPlus IBM VGA8", "Terminus", "Courier New", "Consolas"),
    mono_fonts=("VT323", "Fixedsys Excelsior", "PxPlus IBM VGA8", "Terminus", "Courier New", "Consolas"),
    radius=3, badge_radius=3, uppercase=True, letter_spacing=0.6, title_pt=19, title_spacing=3, row_height=50,
    header_labels={"log": "LOG", "rescan": "RESCAN"},
)

# Warm Carbon & Vivid Orange: carbon surfaces, one orange accent for action and focus, and
# semantic pills (green Full, amber Partial, coral None). Rounded geometry throughout.
_CLEAN_COLORS = {
    "BG": "#111317",                    # warm carbon window
    "SURFACE": "#181B21",               # table, log, panels
    "SURFACE_HOVER": "#1D2027", "SURFACE_SELECTED": "#252A33",
    "HEADER": "#1E222A",                # table header, progress track, quiet pills
    "TEXT": "#F2F4F7",
    "MUTED": "#9AA3B2",                 # secondary metadata
    "MUTED_DIM": "#6E7787",
    "SLATE": "#6E7787", "SLATE_DIM": "#5A6270",   # up-to-date rows
    "BORDER": "#2A2F3A", "BORDER_HOVER": "#3D4452", "BORDER_DIM": "#20242C",
    "ACCENT": "#FF6B1A", "ACCENT_HOVER": "#FF823B", "ACCENT_PRESSED": "#E0580C", "ON_ACCENT": "#FFFFFF",
    "ACCENT_SOFT": "#FF8534",           # text and border of the "To update" pill
    "FOCUS": "#FF6B1A",
    "DISABLED": "#5A6270", "DISABLED_FILL": "#232730",
    "GREEN": "#3DD68C", "AMBER": "#F5B041", "AMBER_BORDER": "#6B5226",
    "RED": "#EB5757", "RED_BORDER": "#6B2C2C",
}

# Pill fills with transparency: (colour, alpha 0-255).
_TINT = {"accent": ("#FF6B1A", round(0.16 * 255)), "full": ("#2ECC71", round(0.14 * 255)),
         "partial": ("#F5B041", round(0.15 * 255)), "none": ("#EB5757", round(0.15 * 255))}


def _clean(c: dict) -> Theme:
    return Theme(
        name=CLEAN, label="[ CLEAN ]", colors=c,
        badges={
            "full": (c["GREEN"], c["GREEN"], 0, False, _TINT["full"], "check"),
            "partial": (c["AMBER"], c["AMBER"], 0, False, _TINT["partial"]),
            "none": (c["RED"], c["RED"], 0, False, _TINT["none"]),
            "accent": (c["ACCENT_SOFT"], c["ACCENT_SOFT"], 0, False, _TINT["accent"]),      # "To update"
            "uptodate": (c["SLATE"], c["HEADER"], 0, False, c["HEADER"]),
            "busy": (c["MUTED"], c["BORDER"], 0, False, c["HEADER"]),
            "ok": (c["GREEN"], c["GREEN"], 0, False, _TINT["full"], "check"),               # "Installed"
            "warn": (c["AMBER"], c["AMBER_BORDER"], 0, False, _TINT["partial"]),
            "alert": (c["RED"], c["RED_BORDER"], 0, False, _TINT["none"]),
        },
        fonts=("Segoe UI Variable Text", "Segoe UI", "Inter", "Roboto", "Cantarell", "Noto Sans", "Ubuntu"),
        mono_fonts=("Cascadia Mono", "Consolas", "JetBrains Mono", "Roboto Mono", "DejaVu Sans Mono"),
        radius=8, badge_radius=11, uppercase=True, letter_spacing=0.6, title_pt=14, title_spacing=1, row_height=52,
        header_labels={"log": "Log", "rescan": "Rescan"}, panel_radius=12, badge_height=22,
    )


CLEAN_THEME = _clean(_CLEAN_COLORS)

_current: Theme = MATRIX_THEME
_fonts_registered = False
_family_cache: dict = {}


# ------------------------------------------------------------------- state
def current() -> Theme:
    return _current


def resolve(name: str | None) -> Theme:
    return CLEAN_THEME if name == CLEAN else MATRIX_THEME


def set_current(name: str) -> Theme:
    """Switch the process-wide theme. Callers re-apply stylesheet() and repaint."""
    global _current
    if name not in NAMES:
        raise ValueError(f"unknown theme {name!r}; choose from {', '.join(NAMES)}")
    _current = resolve(name)
    return _current


def __getattr__(token: str):
    """theme.ACCENT, theme.BG, ... resolve against the current theme; theme.BADGES too."""
    if token == "BADGES":
        return _current.badges
    try:
        return _current.colors[token]
    except KeyError:
        raise AttributeError(token) from None


# ------------------------------------------------------------------- fonts
def register_fonts() -> list[str]:
    """Load the bundled fonts (assets/fonts/*.ttf|otf) into Qt. Needs a QGuiApplication."""
    global _fonts_registered
    from PySide6.QtGui import QFontDatabase
    families: list[str] = []
    if not _fonts_registered:
        for path in sorted(FONT_DIR.glob("*.[ot]tf")):
            font_id = QFontDatabase.addApplicationFont(str(path))
            if font_id >= 0:
                families += QFontDatabase.applicationFontFamilies(font_id)
        _fonts_registered = True
        _family_cache.clear()
    return families


def _pick(candidates: tuple, fixed: bool) -> str:
    key = (candidates, fixed)
    if key not in _family_cache:
        from PySide6.QtGui import QFontDatabase
        installed = set(QFontDatabase.families())
        fallback = QFontDatabase.systemFont(QFontDatabase.FixedFont if fixed else QFontDatabase.GeneralFont).family()
        _family_cache[key] = next((f for f in candidates if f in installed), fallback)
    return _family_cache[key]


def family(mono: bool = False) -> str:
    t = _current
    return _pick(t.mono_fonts if mono else t.fonts, fixed=mono or t.name == MATRIX)


def scale(mono: bool = False) -> float:
    return FONT_SCALE.get(family(mono), 1.0)


def font(point_size: float = 10, bold: bool = False, spacing: float | None = None, mono: bool = False):
    """A QFont in the current theme's family, scaled for pixel fonts."""
    from PySide6.QtGui import QFont
    f = QFont(family(mono))
    f.setStyleHint(QFont.Monospace if (mono or _current.name == MATRIX) else QFont.SansSerif)
    f.setPointSizeF(round(point_size * scale(mono), 1))
    # pixel fonts have no bold cut; synthetic bold smears them
    f.setBold(bold and family(mono) not in FONT_SCALE)
    if spacing:
        f.setLetterSpacing(QFont.AbsoluteSpacing, spacing)
    return f


def mono_font(point_size: float = 10, bold: bool = False, spacing: float = 0.0):
    """Monospace text (versions, hashes): the pixel font in Matrix, a code font in Clean."""
    return font(point_size, bold, spacing, mono=True)


def badge_text(text: str) -> str:
    return text.upper() if _current.uppercase else text


# -------------------------------------------------------------- stylesheet
def stylesheet() -> str:
    t, c = _current, _current.colors
    fam, mono = family(), family(mono=True)
    pt = lambda size, m=False: f"{round(size * scale(m), 1)}pt"   # noqa: E731
    r = t.radius
    bold = "700" if fam not in FONT_SCALE else "400"
    caps_header = "font-weight: 700;" if not t.uppercase else f"font-weight: {bold};"
    metal = _carbon(c, t) if t.name == CLEAN else None      # Clean's own rules, after the shared ones
    header_bg = c["HEADER"] if metal else c["SURFACE"]
    # Progress bar: Matrix = neon fill on the black track; Clean = orange in a rounded carbon track.
    bar_track = c["HEADER"] if metal else c["BG"]
    bar_fill = c["ACCENT"]
    bar_r = 4 if metal else 0
    pr = t.panel_radius
    return f"""
* {{ font-family: '{fam}'; font-size: {pt(10)}; color: {c['TEXT']}; }}
QMainWindow, QWidget#root, QDialog, QMessageBox {{ background: {c['BG']}; }}
QLabel {{ background: transparent; }}

QLabel#title {{ font-size: {pt(t.title_pt)}; font-weight: {bold if t.name == MATRIX else '600'};
               color: {c['ACCENT'] if t.name == MATRIX else c['TEXT']}; letter-spacing: {t.title_spacing}px; }}
QFrame#rule {{ background: {c['BORDER']}; max-height: 1px; min-height: 1px; border: none; }}

QLabel#statusline {{ color: {c['MUTED']}; font-size: {pt(9)}; }}
QLabel#statusline[kind="error"] {{ color: {c['RED']}; }}
QLabel#statusline[kind="warn"] {{ color: {c['AMBER']}; }}
QLabel#statusline[kind="ok"] {{ color: {c['GREEN']}; }}
QProgressBar#progress {{ background: {bar_track}; border: 1px solid {c['BORDER']}; border-radius: {bar_r}px; }}
QProgressBar#progress::chunk {{ background: {bar_fill}; border-radius: {bar_r}px; }}
QLabel#counter {{ color: {c['TEXT'] if not metal else c['MUTED']}; font-family: '{fam if metal else mono}';
                 font-size: {pt(9, not metal)}; }}

QTableView {{ background: {c['SURFACE']}; border: 1px solid {c['BORDER']}; border-radius: {pr}px; outline: 0;
             gridline-color: transparent; selection-background-color: {c['SURFACE_SELECTED']}; }}
QHeaderView {{ background: {header_bg}; border: none; border-top-left-radius: {pr}px; border-top-right-radius: {pr}px; }}
QHeaderView::section {{ background: {header_bg}; color: {c['MUTED_DIM'] if metal is None else c['MUTED']}; border: none;
                        border-bottom: 1px solid {c['BORDER']}; padding: 7px 12px; font-size: {pt(8)}; {caps_header}
                        letter-spacing: {0.8 if metal else 0}px; }}

QPushButton {{ background: {c['SURFACE']}; color: {c['MUTED']}; border: 1px solid {c['BORDER']}; border-radius: {r}px;
              padding: 7px 16px; }}
QPushButton:hover {{ color: {c['ACCENT']}; border-color: {c['ACCENT']}; }}
QPushButton:pressed {{ background: {c['SURFACE_SELECTED']}; }}
QPushButton:disabled {{ color: {c['DISABLED']}; border-color: {c['BORDER_DIM']}; }}
QPushButton:focus {{ border-color: {c['MUTED']}; }}
QPushButton#primary {{ background: {c['ACCENT']}; color: {c['ON_ACCENT']}; border: 1px solid {c['ACCENT']};
                      font-weight: {bold if t.name == MATRIX else '600'}; padding: 9px 22px;
                      letter-spacing: {1 if t.uppercase else 0}px; }}
QPushButton#primary:hover {{ background: {c['ACCENT_HOVER']}; border-color: {c['ACCENT_HOVER']}; }}
QPushButton#primary:focus {{ border: 1px solid {c['FOCUS']}; }}
QPushButton#primary:disabled {{ background: {c['BORDER_DIM']}; color: {c['DISABLED']}; border-color: {c['BORDER']}; }}
QPushButton#ghost {{ background: transparent; border: 1px solid transparent; color: {c['MUTED_DIM']};
                    padding: 4px 8px; font-size: {pt(9)}; }}
QPushButton#ghost:hover, QPushButton#ghost:checked {{ color: {c['ACCENT']}; border-color: {c['BORDER']}; }}
QPushButton#ghost:disabled {{ color: {c['BORDER']}; }}
/* header controls (LOG, theme toggle, RESCAN): one height, one padding, a 1px border */
QPushButton#headerButton {{ background: {c['BG'] if not metal else c['SURFACE']}; color: {c['MUTED']};
                           border: 1px solid {c['BORDER']}; border-radius: {r}px; padding: {'3px 12px' if not metal else '6px 14px'};
                           font-size: {pt(9)}; min-height: {16 if not metal else 18}px; }}
QPushButton#headerButton:hover {{ color: {c['ACCENT']}; border-color: {c['ACCENT']}; }}
QPushButton#headerButton:checked {{ color: {c['ON_ACCENT'] if metal else c['ACCENT']};
                                   background: {c['ACCENT'] if metal else c['SURFACE_SELECTED']}; border-color: {c['ACCENT']}; }}
QPushButton#headerButton:pressed {{ background: {c['SURFACE_SELECTED']}; }}
QPushButton#headerButton:disabled {{ color: {c['DISABLED']}; border-color: {c['BORDER_DIM']}; }}
QPushButton#headerButton:focus {{ border-color: {c['FOCUS']}; }}

QCheckBox {{ color: {c['MUTED']}; spacing: 8px; }}
QCheckBox:hover {{ color: {c['ACCENT']}; }}
QCheckBox:disabled {{ color: {c['DISABLED']}; }}
QCheckBox::indicator {{ width: 14px; height: 14px; border: 1px solid {c['MUTED']};
                       border-radius: {2 if t.name == MATRIX else 4}px; background: {c['BG']}; }}
QCheckBox::indicator:hover {{ border-color: {c['ACCENT']}; }}
QCheckBox::indicator:checked {{ background: {c['ACCENT']}; border-color: {c['ACCENT']}; }}
QCheckBox::indicator:indeterminate {{ background: {c['MUTED_DIM']}; border-color: {c['MUTED']}; }}
QCheckBox::indicator:disabled {{ border-color: {c['BORDER']}; background: {c['BG']}; }}

QPlainTextEdit#log {{ background: {c['BG'] if not metal else c['SURFACE']}; border: 1px solid {c['BORDER']};
                     border-radius: {pr}px; padding: 4px 6px;
                     color: {c['MUTED_DIM']}; font-family: '{mono}'; font-size: {pt(8, True)};
                     selection-background-color: {c['SURFACE_SELECTED']}; }}

QFrame#popover {{ background: {c['SURFACE']}; border: 1px solid {c['BORDER']}; border-radius: {r}px; }}
QLabel#popoverTitle {{ font-weight: {bold}; font-size: {pt(9)}; }}
QLabel#checkLabel {{ color: {c['TEXT']}; font-weight: {bold}; font-size: {pt(9)}; }}
QLabel#checkReason {{ color: {c['MUTED']}; font-size: {pt(8)}; }}

QToolTip {{ background: {c['SURFACE']}; color: {c['TEXT']}; border: 1px solid {c['BORDER']}; padding: 6px;
           font-family: '{fam}'; font-size: {pt(9)}; }}
QMessageBox QLabel {{ color: {c['TEXT']}; }}
QMessageBox QTextEdit {{ background: {c['SURFACE']}; color: {c['MUTED']}; border: 1px solid {c['BORDER']}; }}
QDialog#confirm QLabel {{ color: {c['TEXT']}; font-size: {pt(9)}; }}
QDialog#confirm QLabel#confirmTitle {{ font-weight: {bold}; font-size: {pt(10)}; }}
QDialog#confirm QPlainTextEdit {{ background: {c['SURFACE']}; color: {c['MUTED']}; border: 1px solid {c['BORDER']};
                                  border-radius: {r}px; padding: 4px 6px; font-size: {pt(9)};
                                  selection-background-color: {c['SURFACE_SELECTED']}; }}
QDialog#confirm QPlainTextEdit#confirmList {{ color: {c['TEXT']}; }}
QDialog#confirm QPlainTextEdit#confirmNotes {{ color: {c['MUTED']}; }}

{metal or ''}
QScrollBar:vertical {{ background: {c['SURFACE']}; width: 8px; margin: 0; }}
QScrollBar::handle:vertical {{ background: {c['BORDER']}; min-height: 24px; border-radius: 3px; }}
QScrollBar::handle:vertical:hover {{ background: {c['MUTED_DIM']}; }}
QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; width: 0; }}
QScrollBar::add-page, QScrollBar::sub-page {{ background: none; }}
"""


ICONS = Path(__file__).resolve().parent / "assets" / "icons"


def _icon(name: str) -> str:
    """Path for a stylesheet url(): forward slashes on every platform; Qt picks name@2x.png on
    high-DPI screens by itself."""
    return (ICONS / f"{name}.png").as_posix()


def _carbon(c: dict, t: Theme) -> str:
    """Clean only, after the shared rules (so these win): orange primary action, focus and
    checked states; rounded geometry (8 px controls, 12 px panels, 5 px checkboxes)."""
    r = t.radius
    return f"""
QHeaderView::section:first {{ border-top-left-radius: {t.panel_radius - 1}px; }}
QHeaderView::section:last {{ border-top-right-radius: {t.panel_radius - 1}px; }}
QPushButton {{ background: {c['SURFACE']}; color: {c['MUTED']}; border: 1px solid {c['BORDER']}; border-radius: {r}px; }}
QPushButton:hover {{ color: {c['TEXT']}; border-color: {c['BORDER_HOVER']}; background: {c['SURFACE_HOVER']}; }}
QPushButton:focus {{ border-color: {c['FOCUS']}; }}
QPushButton#primary {{ background: {c['ACCENT']}; color: {c['ON_ACCENT']}; font-weight: 700; border-radius: {r}px;
                      padding: 10px 20px; border: 1px solid {c['ACCENT']}; border-top: 1px solid {c['ACCENT_HOVER']}; }}
QPushButton#primary:hover {{ background: {c['ACCENT_HOVER']}; border-color: {c['ACCENT_HOVER']};
                            border-top: 1px solid #FFA06B; }}
QPushButton#primary:pressed {{ background: {c['ACCENT_PRESSED']}; border-color: {c['ACCENT_PRESSED']}; }}
QPushButton#primary:focus {{ border: 1px solid #FFC29E; }}
QPushButton#primary:disabled {{ background: {c['DISABLED_FILL']}; color: {c['DISABLED']}; border: 1px solid {c['DISABLED_FILL']}; }}
QPushButton#ghost:hover, QPushButton#ghost:checked {{ color: {c['TEXT']}; border-color: {c['BORDER_HOVER']}; }}
QPushButton#headerButton:hover {{ color: {c['TEXT']}; border-color: {c['BORDER_HOVER']}; background: {c['SURFACE_HOVER']}; }}
QPushButton#headerButton:checked {{ color: {c['ON_ACCENT']}; background: {c['ACCENT']}; border-color: {c['ACCENT']}; }}
QTableView:hover {{ border-color: {c['BORDER_HOVER']}; }}
QCheckBox:hover {{ color: {c['TEXT']}; }}
QCheckBox::indicator {{ border-radius: 5px; border-color: {c['BORDER_HOVER']}; background: {c['BG']}; }}
QCheckBox::indicator:hover {{ border-color: {c['ACCENT']}; }}
QCheckBox::indicator:checked {{ background: {c['ACCENT']}; border-color: {c['ACCENT']}; image: url("{_icon('check')}"); }}
QCheckBox::indicator:indeterminate {{ background: {c['ACCENT']}; border-color: {c['ACCENT']}; image: url("{_icon('dash')}"); }}
QCheckBox::indicator:focus {{ border-color: {c['FOCUS']}; }}
QFrame#popover {{ border-color: {c['BORDER_HOVER']}; border-radius: {t.panel_radius}px; }}
QToolTip {{ border-color: {c['BORDER_HOVER']}; border-radius: {r}px; }}
QDialog#confirm QPlainTextEdit {{ border-radius: {t.panel_radius}px; }}
QScrollBar::handle:vertical:hover {{ background: {c['BORDER_HOVER']}; }}
"""
