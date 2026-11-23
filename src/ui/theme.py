"""The Matrix look: near-black terminal surfaces, sharp 1 px borders, capitals and brackets on
the controls, everything tinted by one accent colour. It is the only design; Settings picks the
accent (5 presets) and the font (3 presets), and both apply to the whole window at once.

The current look is process-wide. Colour tokens are read as module attributes (`theme.ACCENT`,
`theme.BG`, ...) and always resolve against it, so painted cells pick up a change on their
next repaint; the window re-applies `stylesheet()`.

Fonts
  VT323  bundled pixel terminal font (SIL OFL, assets/fonts/), registered at start-up; then
         Fixedsys Excelsior, PxPlus IBM VGA8, Terminus, Courier New, Consolas, system mono.
  Mono   Consolas, JetBrains Mono, Cascadia Mono, DejaVu Sans Mono, system mono.
  Sans   Segoe UI, Inter, Roboto, Noto Sans, the system UI font; versions stay monospace.

Semantic colours do not follow the accent: Full and Installed are green, Partial amber, None
and failures red, whatever the accent is.
"""
from __future__ import annotations

import dataclasses
from pathlib import Path

FONT_DIR = Path(__file__).resolve().parent / "assets" / "fonts"
MATRIX = "matrix"

# id -> (label, accent colour). The id is what ui.json stores.
ACCENTS = {
    "green": ("Matrix Green", "#00FF66"),
    "orange": ("Vivid Orange", "#FF6B1A"),
    "cyan": ("Cyan", "#00E5FF"),
    "amber": ("Amber", "#FFB000"),
    "silver": ("Silver", "#E4E8EF"),
}
DEFAULT_ACCENT = "green"

_PIXEL = ("VT323", "Fixedsys Excelsior", "PxPlus IBM VGA8", "Terminus", "Courier New", "Consolas")
_MONO = ("Consolas", "JetBrains Mono", "Cascadia Mono", "DejaVu Sans Mono", "Liberation Mono", "Courier New")
_SANS = ("Segoe UI Variable Text", "Segoe UI", "Inter", "Roboto", "Noto Sans", "Cantarell", "Ubuntu", "DejaVu Sans")


@dataclasses.dataclass(frozen=True)
class FontPreset:
    label: str
    fonts: tuple                        # preferred families for text, best first
    mono_fonts: tuple                   # versions, hashes, the LOG
    fixed: bool                         # fall back to the system monospace font (else the UI font)
    title_pt: float


# id -> preset. The id is what ui.json stores.
FONTS = {
    "vt323": FontPreset("VT323", _PIXEL, _PIXEL, True, 19),
    "mono": FontPreset("Mono", _MONO, _MONO, True, 15),
    "sans": FontPreset("Sans", _SANS, _MONO, False, 15),
}
DEFAULT_FONT = "vt323"

# Pixel fonts draw much smaller than ordinary fonts at the same point size.
FONT_SCALE = {"VT323": 1.5, "Press Start 2P": 0.72}

BG, SURFACE, WHITE = "#050505", "#0D0D0D", "#FFFFFF"
GREEN, AMBER, RED = "#00FF66", "#FFCC00", "#FF3333"


@dataclasses.dataclass(frozen=True)
class Theme:
    name: str
    accent: str                         # ACCENTS id
    font_id: str                        # FONTS id
    colors: dict                        # token -> "#rrggbb"
    badges: dict                        # kind -> (text, border, fill alpha 0-255, glow)
    fonts: tuple
    mono_fonts: tuple
    fixed: bool
    title_pt: float
    radius: int = 3                     # buttons, panels: sharp, terminal-like
    badge_radius: int = 3
    panel_radius: int = 3
    badge_height: int = 20
    uppercase: bool = True              # badge, header and button text in capitals
    letter_spacing: float = 0.6
    title_spacing: int = 3              # px
    row_height: int = 50
    header_labels: dict = dataclasses.field(default_factory=lambda: {
        "log": "LOG", "rescan": "RESCAN", "settings": "[ SETTINGS ]", "update": "UPDATE AVAILABLE"})


# --------------------------------------------------------------- colours
def _rgb(hex_value: str) -> tuple[int, int, int]:
    h = hex_value.lstrip("#")
    return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)


def mix(a: str, b: str, t: float) -> str:
    """t of the way from colour a to colour b."""
    ra, rb = _rgb(a), _rgb(b)
    return "#" + "".join(f"{round(x + (y - x) * t):02X}" for x, y in zip(ra, rb))


# The original Matrix palette, kept exactly for the default accent.
_GREEN_COLORS = {
    "BG": BG, "SURFACE": SURFACE, "SURFACE_HOVER": "#0A1A0F", "SURFACE_SELECTED": "#0F2617",
    "TEXT": "#00FF41", "ACCENT": "#00FF66", "ON_ACCENT": BG, "ACCENT_HOVER": "#00FF41", "ACCENT_BORDER": "#00994D",
    "MUTED": "#00A843", "MUTED_DIM": "#008033", "BORDER": "#1A3320", "BORDER_DIM": "#0F2617",
    "FOCUS": "#CCFFDD", "DISABLED": "#2E5A3A", "SLATE": "#4A6B53", "SLATE_DIM": "#36503D", "SLATE_BORDER": "#24392A",
}


def palette(accent: str) -> dict:
    """Every colour token for an accent: the terminal greys are tinted with it the way the
    original green palette is, so each preset reads as the same design in another phosphor."""
    hex_ = ACCENTS.get(accent, ACCENTS[DEFAULT_ACCENT])[1]
    if hex_ == ACCENTS["green"][1]:
        tinted = dict(_GREEN_COLORS)
    else:
        a = hex_
        tinted = {
            "BG": BG, "SURFACE": SURFACE, "SURFACE_HOVER": mix(BG, a, 0.06), "SURFACE_SELECTED": mix(BG, a, 0.11),
            "TEXT": a, "ACCENT": a, "ON_ACCENT": BG, "ACCENT_HOVER": mix(a, WHITE, 0.25), "ACCENT_BORDER": mix(BG, a, 0.6),
            "MUTED": mix(BG, a, 0.66), "MUTED_DIM": mix(BG, a, 0.5), "BORDER": mix(SURFACE, a, 0.17),
            "BORDER_DIM": mix(BG, a, 0.1), "FOCUS": mix(a, WHITE, 0.8), "DISABLED": mix(BG, a, 0.3),
            "SLATE": mix("#505050", a, 0.15), "SLATE_DIM": mix("#3A3A3A", a, 0.12), "SLATE_BORDER": mix("#262626", a, 0.1),
        }
    return {**tinted, "GREEN": GREEN, "GREEN_BORDER": "#00994D", "AMBER": AMBER, "AMBER_BORDER": "#5C4A00",
            "RED": RED, "RED_BORDER": "#5C1414"}


def _badges(c: dict) -> dict:
    return {
        "full": (c["GREEN"], c["GREEN"], 26, True),
        "partial": (c["AMBER"], c["AMBER_BORDER"], 18, False),
        "none": (c["RED"], c["RED_BORDER"], 18, False),
        "accent": (c["ACCENT"], c["ACCENT_BORDER"], 0, False),     # "To update"
        "uptodate": (c["SLATE"], c["SLATE_BORDER"], 0, False),
        "busy": (c["MUTED_DIM"], c["BORDER"], 0, False),           # "Checking"
        "ok": (c["GREEN"], c["GREEN_BORDER"], 18, False),          # "Installed"
        "warn": (c["AMBER"], c["AMBER_BORDER"], 0, False),         # "Restart required"
        "alert": (c["RED"], c["RED_BORDER"], 0, False),           # "Failed"
    }


def build(accent: str = DEFAULT_ACCENT, font_id: str = DEFAULT_FONT) -> Theme:
    accent = accent if accent in ACCENTS else DEFAULT_ACCENT
    font_id = font_id if font_id in FONTS else DEFAULT_FONT
    c, f = palette(accent), FONTS[font_id]
    return Theme(name=MATRIX, accent=accent, font_id=font_id, colors=c, badges=_badges(c), fonts=f.fonts,
                 mono_fonts=f.mono_fonts, fixed=f.fixed, title_pt=f.title_pt)


MATRIX_THEME = build()
_current: Theme = MATRIX_THEME
_fonts_registered = False
_family_cache: dict = {}


# ------------------------------------------------------------------- state
def current() -> Theme:
    return _current


def configure(accent: str | None = None, font: str | None = None) -> Theme:
    """Change the accent and/or the font, process-wide. Unknown ids raise ValueError. Callers
    re-apply stylesheet() and repaint."""
    global _current
    if accent is not None and accent not in ACCENTS:
        raise ValueError(f"unknown accent {accent!r}; choose from {', '.join(ACCENTS)}")
    if font is not None and font not in FONTS:
        raise ValueError(f"unknown font {font!r}; choose from {', '.join(FONTS)}")
    _current = build(accent or _current.accent, font or _current.font_id)
    return _current


def __getattr__(token: str):
    """theme.ACCENT, theme.BG, ... resolve against the current look; theme.BADGES too."""
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
    return _pick(t.mono_fonts if mono else t.fonts, fixed=mono or t.fixed)


def scale(mono: bool = False) -> float:
    return FONT_SCALE.get(family(mono), 1.0)


def font(point_size: float = 10, bold: bool = False, spacing: float | None = None, mono: bool = False):
    """A QFont in the current family, scaled for pixel fonts."""
    from PySide6.QtGui import QFont
    f = QFont(family(mono))
    f.setStyleHint(QFont.Monospace if (mono or _current.fixed) else QFont.SansSerif)
    f.setPointSizeF(round(point_size * scale(mono), 1))
    # pixel fonts have no bold cut; synthetic bold smears them
    f.setBold(bold and family(mono) not in FONT_SCALE)
    if spacing:
        f.setLetterSpacing(QFont.AbsoluteSpacing, spacing)
    return f


def mono_font(point_size: float = 10, bold: bool = False, spacing: float = 0.0):
    """Monospace text (versions, hashes): the pixel font with VT323, a code font otherwise."""
    return font(point_size, bold, spacing, mono=True)


def badge_text(text: str) -> str:
    return text.upper() if _current.uppercase else text


# -------------------------------------------------------------- stylesheet
ICONS = Path(__file__).resolve().parent / "assets" / "icons"


def _icon(name: str) -> str:
    """Path for a stylesheet url() (near-black tick and dash, drawn on the accent): forward
    slashes on every platform; Qt picks name@2x.png on high-DPI screens by itself."""
    return (ICONS / f"{name}.png").as_posix()


def stylesheet() -> str:
    t, c = _current, _current.colors
    fam, mono = family(), family(mono=True)
    pt = lambda size, m=False: f"{round(size * scale(m), 1)}pt"   # noqa: E731
    r = t.radius
    bold = "700" if fam not in FONT_SCALE else "400"
    return f"""
* {{ font-family: '{fam}'; font-size: {pt(10)}; color: {c['TEXT']}; }}
QMainWindow, QWidget#root, QDialog, QMessageBox {{ background: {c['BG']}; }}
QLabel {{ background: transparent; }}

QLabel#title {{ font-size: {pt(t.title_pt)}; font-weight: {bold}; color: {c['ACCENT']}; letter-spacing: {t.title_spacing}px; }}
QFrame#rule {{ background: {c['BORDER']}; max-height: 1px; min-height: 1px; border: none; }}

QLabel#statusline {{ color: {c['MUTED']}; font-size: {pt(9)}; }}
QLabel#statusline[kind="error"] {{ color: {c['RED']}; }}
QLabel#statusline[kind="warn"] {{ color: {c['AMBER']}; }}
QLabel#statusline[kind="ok"] {{ color: {c['GREEN']}; }}
QProgressBar#progress {{ background: {c['BG']}; border: 1px solid {c['BORDER']}; border-radius: 0px; }}
QProgressBar#progress::chunk {{ background: {c['ACCENT']}; }}
QLabel#counter {{ color: {c['TEXT']}; font-family: '{mono}'; font-size: {pt(9, True)}; }}

QTableView {{ background: {c['SURFACE']}; border: 1px solid {c['BORDER']}; border-radius: {t.panel_radius}px; outline: 0;
             gridline-color: transparent; selection-background-color: {c['SURFACE_SELECTED']}; }}
QHeaderView {{ background: {c['SURFACE']}; border: none; }}
QHeaderView::section {{ background: {c['SURFACE']}; color: {c['MUTED_DIM']}; border: none;
                        border-bottom: 1px solid {c['BORDER']}; padding: 7px 12px; font-size: {pt(8)}; font-weight: {bold}; }}

QPushButton {{ background: {c['SURFACE']}; color: {c['MUTED']}; border: 1px solid {c['BORDER']}; border-radius: {r}px;
              padding: 7px 16px; }}
QPushButton:hover {{ color: {c['ACCENT']}; border-color: {c['ACCENT']}; }}
QPushButton:pressed {{ background: {c['SURFACE_SELECTED']}; }}
QPushButton:disabled {{ color: {c['DISABLED']}; border-color: {c['BORDER_DIM']}; }}
QPushButton:focus {{ border-color: {c['MUTED']}; }}
QPushButton#primary {{ background: {c['ACCENT']}; color: {c['ON_ACCENT']}; border: 1px solid {c['ACCENT']};
                      font-weight: {bold}; padding: 9px 22px; letter-spacing: 1px; }}
QPushButton#primary:hover {{ background: {c['ACCENT_HOVER']}; border-color: {c['ACCENT_HOVER']}; }}
QPushButton#primary:focus {{ border: 1px solid {c['FOCUS']}; }}
QPushButton#primary:disabled {{ background: {c['BORDER_DIM']}; color: {c['DISABLED']}; border-color: {c['BORDER']}; }}
QPushButton#ghost {{ background: transparent; border: 1px solid transparent; color: {c['MUTED_DIM']};
                    padding: 4px 8px; font-size: {pt(9)}; }}
QPushButton#ghost:hover, QPushButton#ghost:checked {{ color: {c['ACCENT']}; border-color: {c['BORDER']}; }}
QPushButton#ghost:disabled {{ color: {c['BORDER']}; }}
/* header controls (LOG, SETTINGS, RESCAN, UPDATE AVAILABLE): one height, one padding, a 1px border */
QPushButton#headerButton, QPushButton#updateButton {{ background: {c['BG']}; color: {c['MUTED']};
                           border: 1px solid {c['BORDER']}; border-radius: {r}px; padding: 3px 12px;
                           font-size: {pt(9)}; min-height: 16px; }}
QPushButton#headerButton:hover {{ color: {c['ACCENT']}; border-color: {c['ACCENT']}; }}
QPushButton#headerButton:checked {{ color: {c['ACCENT']}; background: {c['SURFACE_SELECTED']}; border-color: {c['ACCENT']}; }}
QPushButton#headerButton:pressed {{ background: {c['SURFACE_SELECTED']}; }}
QPushButton#headerButton:disabled {{ color: {c['DISABLED']}; border-color: {c['BORDER_DIM']}; }}
QPushButton#headerButton:focus {{ border-color: {c['FOCUS']}; }}
QPushButton#updateButton {{ color: {c['ACCENT']}; border-color: {c['ACCENT']}; background: {c['SURFACE_SELECTED']}; }}
QPushButton#updateButton:hover {{ color: {c['ON_ACCENT']}; background: {c['ACCENT']}; }}
QPushButton#updateButton:focus {{ border-color: {c['FOCUS']}; }}

QCheckBox {{ color: {c['MUTED']}; spacing: 8px; }}
QCheckBox:hover {{ color: {c['ACCENT']}; }}
QCheckBox:disabled {{ color: {c['DISABLED']}; }}
QCheckBox::indicator {{ width: 14px; height: 14px; border: 1px solid {c['MUTED']}; border-radius: 2px; background: {c['BG']}; }}
QCheckBox::indicator:hover {{ border-color: {c['ACCENT']}; }}
QCheckBox::indicator:checked {{ background: {c['ACCENT']}; border-color: {c['ACCENT']}; image: url("{_icon('check')}"); }}
QCheckBox::indicator:indeterminate {{ background: {c['MUTED_DIM']}; border-color: {c['MUTED']}; image: url("{_icon('dash')}"); }}
QCheckBox::indicator:disabled {{ border-color: {c['BORDER']}; background: {c['BG']}; }}

QPlainTextEdit#log {{ background: {c['BG']}; border: 1px solid {c['BORDER']}; border-radius: {t.panel_radius}px; padding: 4px 6px;
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

QDialog#settings {{ border: 1px solid {c['BORDER']}; }}
QDialog#settings QLabel#settingsTitle {{ color: {c['ACCENT']}; font-weight: {bold}; font-size: {pt(11)}; letter-spacing: 2px; }}
QDialog#settings QLabel#settingsSection {{ color: {c['MUTED_DIM']}; font-size: {pt(8)}; letter-spacing: 1px; }}
QDialog#settings QFrame#rule {{ background: {c['BORDER']}; }}
QPushButton#preset {{ background: {c['BG']}; color: {c['MUTED']}; border: 1px solid {c['BORDER']}; border-radius: {r}px;
                     padding: 5px 10px; font-size: {pt(9)}; text-align: left; }}
QPushButton#preset:hover {{ color: {c['ACCENT']}; border-color: {c['ACCENT']}; }}
QPushButton#preset:checked {{ color: {c['ACCENT']}; border-color: {c['ACCENT']}; background: {c['SURFACE_SELECTED']}; }}
QPushButton#preset:focus {{ border-color: {c['FOCUS']}; }}

QScrollBar:vertical {{ background: {c['SURFACE']}; width: 8px; margin: 0; }}
QScrollBar::handle:vertical {{ background: {c['BORDER']}; min-height: 24px; border-radius: 0px; }}
QScrollBar::handle:vertical:hover {{ background: {c['MUTED_DIM']}; }}
QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; width: 0; }}
QScrollBar::add-page, QScrollBar::sub-page {{ background: none; }}
"""
