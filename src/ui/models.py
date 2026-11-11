"""DriverTableModel: one row per available update, then one per up-to-date device.

Selection lives here, not in the widgets, so "Select all fully checked" and the install
button can be driven and tested without clicking. Only rows whose verification is Full or
Partial, and that have not been installed yet, can be selected.
"""
from __future__ import annotations

import dataclasses

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt, Signal

from core import engine
from . import verification as vf

COL_DEVICE, COL_STATUS, COL_VERIFY, COL_SELECT = range(4)
HEADERS = ["DEVICE", "STATUS", "VERIFICATION", ""]

BadgeRole = Qt.UserRole + 1        # (text, kind) for the Status and Verification cells
SubtitleRole = Qt.UserRole + 2     # second line of the device cell
HelpRole = Qt.UserRole + 3         # True where the (?) target is drawn
RowRole = Qt.UserRole + 4          # the DriverRow
MutedRole = Qt.UserRole + 5        # True for rows without an update


def _is_checked(value) -> bool:
    try:
        return Qt.CheckState(value) == Qt.Checked
    except (TypeError, ValueError):
        return bool(value) and value not in (0, Qt.Unchecked)


@dataclasses.dataclass(eq=False)
class DriverRow:
    device: object
    update: object = None            # core.model.Update, or None when the device is up to date
    selected: bool = False
    outcome: dict | None = None      # result item from the installer, once installed or failed

    @property
    def level(self) -> str:
        return vf.level(self.update)

    @property
    def selectable(self) -> bool:
        return (self.update is not None and self.outcome is None and self.level in (vf.FULL, vf.PARTIAL)
                and self.update.status in ("verified", "delegated"))

    @property
    def key(self) -> str:
        return engine.update_key(self.update) if self.update is not None else ""


class DriverTableModel(QAbstractTableModel):
    selectionChanged = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.rows: list[DriverRow] = []

    # ------------------------------------------------------------- loading
    def load(self, devices, updates) -> None:
        self.beginResetModel()
        with_update = {id(u.device) for u in updates}
        rows = [DriverRow(u.device, u) for u in updates]
        rows.sort(key=lambda r: (vf.RANK.get(r.level, 9), r.device.name.lower()))
        rows += sorted((DriverRow(d) for d in devices if id(d) not in with_update),
                       key=lambda r: r.device.name.lower())
        self.rows = rows
        self.endResetModel()
        self.selectionChanged.emit()

    def refresh_update(self, update) -> None:
        """Repaint the row(s) of one update after its verification finished."""
        for i, row in enumerate(self.rows):
            if row.update is update:
                if row.selected and not row.selectable:
                    row.selected = False
                self.dataChanged.emit(self.index(i, 0), self.index(i, COL_SELECT))
        self.selectionChanged.emit()

    def refresh_all(self) -> None:
        for row in self.rows:
            if row.selected and not row.selectable:
                row.selected = False
        if self.rows:
            self.dataChanged.emit(self.index(0, 0), self.index(len(self.rows) - 1, COL_SELECT))
        self.selectionChanged.emit()

    def apply_outcomes(self, items: list[dict]) -> None:
        by_id = {i.get("id"): i for i in items}
        for row in self.rows:
            if row.update is not None and row.key in by_id:
                row.outcome = by_id[row.key]
                row.selected = False
        self.refresh_all()

    # ----------------------------------------------------------- selection
    def selected_updates(self) -> list:
        return [r.update for r in self.rows if r.selected and r.selectable]

    def full_rows(self) -> list[DriverRow]:
        return [r for r in self.rows if r.selectable and r.level == vf.FULL]

    def full_state(self) -> Qt.CheckState:
        """State of "Select all fully checked": all / none / some of the Full rows selected."""
        full = self.full_rows()
        chosen = sum(r.selected for r in full)
        if not full or chosen == 0:
            return Qt.Unchecked
        return Qt.Checked if chosen == len(full) else Qt.PartiallyChecked

    def set_full_selected(self, on: bool) -> None:
        """Select or deselect every Full row. Partial rows chosen by hand are left alone."""
        for r in self.full_rows():
            r.selected = on
        self.refresh_all()

    def set_selected(self, row: int, on: bool) -> bool:
        r = self.rows[row]
        if not r.selectable or r.selected == on:
            return False
        r.selected = on
        self.dataChanged.emit(self.index(row, 0), self.index(row, COL_SELECT))
        self.selectionChanged.emit()
        return True

    def counts(self) -> dict:
        return {"updates": sum(r.update is not None and r.outcome is None for r in self.rows),
                "selected": len(self.selected_updates()), "devices": len(self.rows),
                "pending": sum(r.level == vf.PENDING for r in self.rows),
                "full": len(self.full_rows())}

    # ------------------------------------------------------------ Qt model
    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(HEADERS)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return HEADERS[section]
        if orientation == Qt.Horizontal and role == Qt.TextAlignmentRole:
            return int(Qt.AlignLeft | Qt.AlignVCenter)
        return None

    def row(self, index) -> DriverRow:
        return self.rows[index.row()]

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        r, col, u = self.rows[index.row()], index.column(), self.rows[index.row()].update
        if role == RowRole:
            return r
        if role == MutedRole:
            return u is None or (r.outcome is not None and r.outcome.get("status") == "no-op")
        if col == COL_DEVICE:
            if role == Qt.DisplayRole:
                return r.device.name
            if role == SubtitleRole:
                if u is None:
                    return f"{r.device.driver_version or 'driver version unknown'} · no newer driver found"
                return f"{u.installed} → {u.available} · {u.source}"
            if role == Qt.ToolTipRole:
                ids = ", ".join(h for h in r.device.hardware_ids if not h.startswith("raw:"))[:200]
                return f"{r.device.name}\n{ids}" if ids else r.device.name
        elif col == COL_STATUS:
            text, kind = vf.row_status(u, r.outcome)
            if role in (Qt.DisplayRole, Qt.AccessibleTextRole):
                return text
            if role == BadgeRole:
                return text, kind
            if role == Qt.ToolTipRole:
                if r.outcome:
                    return r.outcome.get("detail") or text
                return u.detail if u is not None and u.detail else None
        elif col == COL_VERIFY:
            lvl = r.level
            if role in (Qt.DisplayRole, Qt.AccessibleTextRole):
                return lvl or "—"
            if role == BadgeRole:
                return (lvl, vf.KIND[lvl]) if lvl else None
            if role == HelpRole:
                return lvl == vf.PARTIAL
            if role in (Qt.ToolTipRole, Qt.AccessibleDescriptionRole):
                return vf.explain(u) if u is not None and u.checks else None
        elif col == COL_SELECT:
            if role == Qt.CheckStateRole and r.selectable:
                return Qt.Checked if r.selected else Qt.Unchecked
            if role == Qt.AccessibleTextRole:
                return "selected" if r.selected else "not selected"
        return None

    def flags(self, index):
        if not index.isValid():
            return Qt.NoItemFlags
        base = Qt.ItemIsEnabled | Qt.ItemIsSelectable
        if index.column() == COL_SELECT and self.rows[index.row()].selectable:
            base |= Qt.ItemIsUserCheckable
        return base

    def setData(self, index, value, role=Qt.EditRole):
        if index.isValid() and index.column() == COL_SELECT and role == Qt.CheckStateRole:
            return self.set_selected(index.row(), _is_checked(value))
        return False
