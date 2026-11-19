"""Painted cells: badges with the (?) help target, two-line device names, centred checkboxes.

Badges are drawn, not built from widgets, so long device lists stay fast. All delegates paint
their own row background (hover, current row) and a thin separator line. Colours, fonts, radii
and capitalisation come from the current theme at paint time, so a theme switch only needs a
repaint.
"""
from __future__ import annotations

from PySide6.QtCore import QEvent, QModelIndex, QObject, QPoint, QPointF, QRect, QRectF, QSize, Qt, QTimer, Signal
from PySide6.QtGui import QColor, QFontMetrics, QPainter, QPen
from PySide6.QtWidgets import QStyle, QStyledItemDelegate, QToolTip

from . import theme
from .models import COL_STATUS, BadgeRole, HelpRole, MutedRole, SpinnerRole, SubtitleRole

PAD_X = 12
BADGE_H = 20
HELP_D = 16
ICON_W = 12                     # tick drawn before the text of badges whose theme asks for one
SPIN_D = 14                     # loading spinner beside a "Queued" / "Scanning…" / "Checking…" pill
TERMINAL_FRAMES = "|/-\\"        # Matrix: a terminal spinner, one character per frame


class Spinner(QObject):
    """One animation clock for every loading row. Repaints only the Status column of the view,
    and runs only while the model reports spinning rows, so an idle window uses no CPU."""
    INTERVAL_MS = 80
    STEPS = 12                          # 30 degrees per frame for the arc

    def __init__(self, view):
        super().__init__(view)
        self.view, self.step = view, 0
        self.timer = QTimer(self, interval=self.INTERVAL_MS)
        self.timer.timeout.connect(self._tick)

    def set_running(self, on: bool) -> None:
        if on and not self.timer.isActive():
            self.timer.start()
        elif not on and self.timer.isActive():
            self.timer.stop()
            self._repaint()

    @property
    def running(self) -> bool:
        return self.timer.isActive()

    def _tick(self) -> None:
        self.step = (self.step + 1) % (self.STEPS * len(TERMINAL_FRAMES))
        self._repaint()

    def _repaint(self) -> None:
        x = self.view.columnViewportPosition(COL_STATUS)
        port = self.view.viewport()
        port.update(QRect(x, 0, self.view.columnWidth(COL_STATUS), port.height()))


def paint_spinner(painter, rect: QRectF, step: int, color: QColor) -> None:
    if theme.current().name == theme.MATRIX:
        painter.setFont(theme.font(11, mono=True))
        painter.setPen(color)
        painter.drawText(rect, Qt.AlignCenter, TERMINAL_FRAMES[step % len(TERMINAL_FRAMES)])
        return
    pen = QPen(color, 1.8)
    pen.setCapStyle(Qt.RoundCap)
    painter.setPen(pen)
    painter.setBrush(Qt.NoBrush)
    arc = rect.adjusted(2, 2, -2, -2)
    # Qt angles: 1/16 degree, counter-clockwise; minus = clockwise rotation
    painter.drawArc(arc, int(-step * (360 / Spinner.STEPS) * 16), 270 * 16)


def badge_style(kind: str) -> tuple:
    """(text colour, border, fill alpha, glow, explicit fill or None, icon or None)."""
    style = tuple(theme.BADGES.get(kind, theme.BADGES["busy"]))
    return style + (None,) * (6 - len(style))


def _color(hex_value: str, alpha: int = 255) -> QColor:
    c = QColor(hex_value)
    c.setAlpha(alpha)
    return c


class _Base(QStyledItemDelegate):
    def paint_background(self, painter: QPainter, option) -> None:
        painter.save()
        if option.state & QStyle.State_Selected:
            painter.fillRect(option.rect, _color(theme.SURFACE_SELECTED))
        elif option.state & QStyle.State_MouseOver:
            painter.fillRect(option.rect, _color(theme.SURFACE_HOVER))
        painter.setPen(QPen(_color(theme.BORDER_DIM), 1))
        painter.drawLine(option.rect.bottomLeft(), option.rect.bottomRight())
        painter.restore()

    def sizeHint(self, option, index):
        return QSize(super().sizeHint(option, index).width(), theme.current().row_height)


class NameDelegate(_Base):
    """Device name on top; versions and source (or hardware state) underneath in muted mono."""

    def paint(self, painter, option, index):
        self.paint_background(painter, option)
        muted = bool(index.data(MutedRole))
        rect = option.rect.adjusted(PAD_X, 7, -PAD_X, -7)
        name_font, sub_font = theme.font(10, bold=not muted), theme.mono_font(8)
        painter.save()
        painter.setFont(name_font)
        painter.setPen(_color(theme.SLATE if muted else theme.TEXT))
        fm = QFontMetrics(name_font)
        painter.drawText(QRect(rect.left(), rect.top(), rect.width(), fm.height()), Qt.AlignLeft | Qt.AlignVCenter,
                         fm.elidedText(index.data(Qt.DisplayRole) or "", Qt.ElideRight, rect.width()))
        sub = index.data(SubtitleRole) or ""
        if sub:
            painter.setFont(sub_font)
            painter.setPen(_color(theme.SLATE_DIM if muted else theme.MUTED))
            sfm = QFontMetrics(sub_font)
            painter.drawText(QRect(rect.left(), rect.bottom() - sfm.height() + 1, rect.width(), sfm.height()),
                             Qt.AlignLeft | Qt.AlignVCenter, sfm.elidedText(sub, Qt.ElideMiddle, rect.width()))
        painter.restore()


class BadgeDelegate(_Base):
    """Pill badge from BadgeRole; for Partial (HelpRole) also a clickable (?) target; for rows
    still loading (SpinnerRole) an animated spinner after the pill, driven by `spinner`.

    Hovering the cell shows the itemised checks as a tooltip; clicking (?) emits helpRequested
    with the global point under the (?), where the window opens the pinned check list."""
    helpRequested = Signal(QModelIndex, QPoint)

    def __init__(self, parent=None, spinner: Spinner | None = None):
        super().__init__(parent)
        self.spinner = spinner

    @classmethod
    def spinner_rect(cls, cell: QRect, text: str, kind: str | None = None) -> QRect:
        badge = cls.badge_rect(cell, text, kind)
        return QRect(badge.right() + 8, cell.center().y() - SPIN_D // 2 + 1, SPIN_D, SPIN_D)

    @staticmethod
    def badge_font():
        t = theme.current()
        return theme.font(8, bold=True, spacing=t.letter_spacing or None, mono=t.name == theme.MATRIX)

    @classmethod
    def badge_rect(cls, cell: QRect, text: str, kind: str | None = None) -> QRect:
        fm = QFontMetrics(cls.badge_font())
        icon = kind is not None and badge_style(kind)[5] == "check"
        width = fm.horizontalAdvance(theme.badge_text(text)) + 18 + (ICON_W + 4 if icon else 0)
        return QRect(cell.left() + PAD_X, cell.center().y() - BADGE_H // 2 + 1, width, BADGE_H)

    @classmethod
    def help_rect(cls, cell: QRect, text: str, kind: str | None = None) -> QRect:
        badge = cls.badge_rect(cell, text, kind)
        return QRect(badge.right() + 8, cell.center().y() - HELP_D // 2 + 1, HELP_D, HELP_D)

    def paint(self, painter, option, index):
        self.paint_background(painter, option)
        badge = index.data(BadgeRole)
        painter.save()
        painter.setRenderHint(QPainter.Antialiasing)
        if not badge:
            painter.setFont(theme.font(9))
            painter.setPen(_color(theme.BORDER))
            painter.drawText(option.rect.adjusted(PAD_X, 0, 0, 0), Qt.AlignLeft | Qt.AlignVCenter, "—")
            painter.restore()
            return
        text, kind = badge
        fg, border, fill_alpha, glow, fill, icon = badge_style(kind)
        rect = QRectF(self.badge_rect(option.rect, text, kind))
        radius = min(theme.current().badge_radius, rect.height() / 2)
        if glow:
            painter.setPen(QPen(_color(fg, 45), 3))
            painter.setBrush(Qt.NoBrush)
            painter.drawRoundedRect(rect.adjusted(-1, -1, 1, 1), radius + 1, radius + 1)
        painter.setPen(QPen(_color(border), 1))
        painter.setBrush(_color(fill) if fill else (_color(fg, fill_alpha) if fill_alpha else Qt.NoBrush))
        painter.drawRoundedRect(rect.adjusted(0.5, 0.5, -0.5, -0.5), radius, radius)
        text_rect = rect
        if icon == "check":
            x, y = rect.left() + 9, rect.center().y()
            pen = QPen(_color(fg), 1.6)
            pen.setCapStyle(Qt.RoundCap)
            pen.setJoinStyle(Qt.RoundJoin)
            painter.setPen(pen)
            painter.drawPolyline([QPointF(x, y), QPointF(x + 3.5, y + 3.5), QPointF(x + ICON_W - 2, y - 4)])
            text_rect = rect.adjusted(ICON_W + 4, 0, 0, 0)
        painter.setFont(self.badge_font())
        painter.setPen(_color(fg))
        painter.drawText(text_rect, Qt.AlignCenter, theme.badge_text(text))
        if index.data(HelpRole):
            help_rect = QRectF(self.help_rect(option.rect, text, kind))
            hovered = bool(option.state & QStyle.State_MouseOver)
            painter.setPen(QPen(_color(theme.AMBER if hovered else theme.AMBER_BORDER), 1))
            painter.setBrush(_color(theme.AMBER, 30 if hovered else 0))
            painter.drawEllipse(help_rect.adjusted(0.5, 0.5, -0.5, -0.5))
            painter.setFont(theme.font(8, bold=True))
            painter.setPen(_color(theme.AMBER))
            painter.drawText(help_rect, Qt.AlignCenter, "?")
        if index.data(SpinnerRole):
            step = self.spinner.step if self.spinner else 0
            paint_spinner(painter, QRectF(self.spinner_rect(option.rect, text, kind)), step, _color(theme.ACCENT, 200))
        painter.restore()

    def editorEvent(self, event, model, option, index):
        if (event.type() == QEvent.MouseButtonRelease and event.button() == Qt.LeftButton
                and index.data(HelpRole)):
            text, kind = index.data(BadgeRole)
            target = self.help_rect(option.rect, text, kind).adjusted(-4, -4, 4, 4)
            if target.contains(event.position().toPoint()):
                widget = option.widget
                anchor = self.help_rect(option.rect, text, kind).bottomLeft() + QPoint(0, 6)
                self.helpRequested.emit(index, widget.mapToGlobal(anchor) if widget else anchor)
                return True
        return super().editorEvent(event, model, option, index)

    def helpEvent(self, event, view, option, index):
        if event.type() == QEvent.ToolTip:
            text = index.data(Qt.ToolTipRole)
            if text:
                QToolTip.showText(event.globalPos(), text, view)
            else:
                QToolTip.hideText()
            return True
        return super().helpEvent(event, view, option, index)


class CheckDelegate(_Base):
    """Centred square checkbox; empty for rows that cannot be selected."""

    def paint(self, painter, option, index):
        self.paint_background(painter, option)
        state = index.data(Qt.CheckStateRole)
        if state is None:
            return
        checked = state in (Qt.Checked, Qt.Checked.value)
        box = QRectF(option.rect.center().x() - 7, option.rect.center().y() - 6, 14, 14)
        hovered = bool(option.state & QStyle.State_MouseOver)
        painter.save()
        painter.setRenderHint(QPainter.Antialiasing)
        painter.setPen(QPen(_color(theme.ACCENT if (checked or hovered) else theme.MUTED), 1))
        painter.setBrush(_color(theme.ACCENT) if checked else _color(theme.BG))
        corner = 2 if theme.current().name == theme.MATRIX else 4
        painter.drawRoundedRect(box.adjusted(0.5, 0.5, -0.5, -0.5), corner, corner)
        if checked:
            pen = QPen(_color(theme.ON_ACCENT), 2)
            pen.setCapStyle(Qt.RoundCap)
            painter.setPen(pen)
            painter.drawPolyline([box.topLeft() + p for p in (QPoint(3, 7), QPoint(6, 10), QPoint(11, 4))])
        painter.restore()

    def editorEvent(self, event, model, option, index):
        if not (index.flags() & Qt.ItemIsUserCheckable):
            return False
        toggle = (event.type() == QEvent.MouseButtonRelease and event.button() == Qt.LeftButton
                  and option.rect.contains(event.position().toPoint()))
        toggle = toggle or (event.type() == QEvent.KeyPress and event.key() in (Qt.Key_Space, Qt.Key_Select))
        if toggle:
            current = index.data(Qt.CheckStateRole) in (Qt.Checked, Qt.Checked.value)
            return model.setData(index, Qt.Unchecked if current else Qt.Checked, Qt.CheckStateRole)
        return event.type() in (QEvent.MouseButtonPress, QEvent.MouseButtonDblClick)
