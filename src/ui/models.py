"""DriverTableModel: one row per available update, then one per up-to-date device.

Rows appear as soon as the hardware is enumerated (phase "queued"), turn "scanning" while
their own online lookup runs, and settle in place when the result arrives: a row with an
update moves up and shows its verification while it is downloaded and checked; a device
without a newer driver becomes "Up to date". Rows that are queued, scanning or still being
verified report SpinnerRole, and spinningChanged tells the view when to run its animation.

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
HelpRole = Qt.UserRole + 3         # True where the (?) target is drawn (Partial and None)
RowRole = Qt.UserRole + 4          # the DriverRow
MutedRole = Qt.UserRole + 5        # True for rows without an update
SpinnerRole = Qt.UserRole + 6      # True while the row is queued, being looked up or being verified

QUEUED, SCANNING, DONE, NOT_CHECKED = "queued", "scanning", "done", "not-checked"


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
    phase: str = DONE                # QUEUED / SCANNING until this device's lookup is final
    order: int = 0                   # enumeration order: rows still being looked up keep it

    @property
    def level(self) -> str:
        return vf.level(self.update)

    @property
    def spinning(self) -> bool:
        if self.phase in (QUEUED, SCANNING):
            return True
        return (self.phase == DONE and self.update is not None and self.outcome is None
                and self.level == vf.PENDING)

    @property
    def selectable(self) -> bool:
        return (self.update is not None and self.outcome is None and self.level in (vf.FULL, vf.PARTIAL)
                and self.update.status in ("verified", "delegated"))

    @property
    def key(self) -> str:
        return engine.update_key(self.update) if self.update is not None else ""


class DriverTableModel(QAbstractTableModel):
    selectionChanged = Signal()
    spinningChanged = Signal(bool)     # any row animating; the view runs its timer only then

    def __init__(self, parent=None):
        super().__init__(parent)
        self.rows: list[DriverRow] = []
        self._spinning = False

    # ------------------------------------------------------------- loading
    def load(self, devices, updates) -> None:
        """Everything at once (finished scans, tests)."""
        self.beginResetModel()
        with_update = {id(u.device) for u in updates}
        rows = [DriverRow(u.device, u) for u in updates]
        rows += [DriverRow(d) for d in devices if id(d) not in with_update]
        for n, row in enumerate(rows):
            row.order = n
        self.rows = sorted(rows, key=self._sort_key)
        self.endResetModel()
        self._changed()

    def load_devices(self, devices) -> None:
        """Stage 1: every enumerated device, queued for its online lookup."""
        self.beginResetModel()
        self.rows = [DriverRow(d, phase=QUEUED, order=n) for n, d in enumerate(devices)]
        self.endResetModel()
        self._changed()

    def mark_scanning(self, device) -> None:
        for i, row in enumerate(self.rows):
            if row.device is device and row.phase == QUEUED:
                row.phase = SCANNING
                self._repaint(i)
        self._sync_spinning()

    def set_device_result(self, device, updates) -> None:
        """Stage 2: this device's lookup is final. Its row shows the update (moving up, its
        verification still pending) or settles as up to date; a device that was not
        enumerated (e.g. Linux "This computer") gets new rows."""
        mine = [r for r in self.rows if r.device is device and r.phase != DONE]
        if not mine and not updates:
            return
        updates = list(updates)
        if mine:
            first = mine[0]
            first.phase, first.update = DONE, (updates.pop(0) if updates else None)
            for extra in mine[1:]:
                extra.phase = DONE
        order = mine[0].order if mine else len(self.rows)
        if updates:
            self.beginInsertRows(QModelIndex(), len(self.rows), len(self.rows) + len(updates) - 1)
            self.rows += [DriverRow(device, u, order=order) for u in updates]
            self.endInsertRows()
        if mine:
            for i, row in enumerate(self.rows):
                if row in mine:
                    self._repaint(i)
        self._resort()
        self._changed()

    def finish_pending(self) -> None:
        """The scan ended (or failed): rows whose lookup or verification never finished say so
        instead of spinning forever."""
        for i, row in enumerate(self.rows):
            if row.spinning:
                row.phase = NOT_CHECKED
                row.selected = False
                self._repaint(i)
        self._changed()

    def refresh_update(self, update) -> None:
        """Repaint the row(s) of one update after its verification finished, and re-sort by level."""
        for i, row in enumerate(self.rows):
            if row.update is update:
                if row.selected and not row.selectable:
                    row.selected = False
                self._repaint(i)
        self._resort()
        self._changed()

    # ------------------------------------------------------------- order
    @staticmethod
    def _sort_key(row: DriverRow):
        """Updates first (Full, Partial, pending, None), then rows still being looked up in
        enumeration order (so they do not jump around), then devices without an update."""
        name = row.device.name.lower()
        if row.update is not None:
            return 0, vf.RANK.get(row.level, 9), name, row.order
        if row.phase in (QUEUED, SCANNING, NOT_CHECKED):
            return 1, 0, "", row.order
        return 2, 0, name, row.order

    def _resort(self) -> None:
        ordered = sorted(self.rows, key=self._sort_key)
        if ordered == self.rows:
            return
        self.layoutAboutToBeChanged.emit()
        old = self.rows
        self.rows = ordered
        where = {id(r): i for i, r in enumerate(ordered)}
        before = self.persistentIndexList()
        after = [self.index(where[id(old[ix.row()])], ix.column()) for ix in before]
        self.changePersistentIndexList(before, after)
        self.layoutChanged.emit()

    def _repaint(self, i: int) -> None:
        self.dataChanged.emit(self.index(i, 0), self.index(i, COL_SELECT))

    def _changed(self) -> None:
        self.selectionChanged.emit()
        self._sync_spinning()

    def _sync_spinning(self) -> None:
        now = any(r.spinning for r in self.rows)
        if now != self._spinning:
            self._spinning = now
            self.spinningChanged.emit(now)

    @property
    def spinning(self) -> bool:
        return self._spinning

    def refresh_all(self) -> None:
        for row in self.rows:
            if row.selected and not row.selectable:
                row.selected = False
        if self.rows:
            self.dataChanged.emit(self.index(0, 0), self.index(len(self.rows) - 1, COL_SELECT))
        self._changed()

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
                "full": len(self.full_rows()),
                "looking": sum(r.phase in (QUEUED, SCANNING) for r in self.rows),
                "not_checked": sum(r.phase == NOT_CHECKED for r in self.rows)}

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
            return ((u is None and r.phase == DONE)
                    or (r.outcome is not None and r.outcome.get("status") == "no-op"))
        if role == SpinnerRole:
            return col == COL_STATUS and r.spinning
        if col == COL_DEVICE:
            if role == Qt.DisplayRole:
                return r.device.name
            if role == SubtitleRole:
                if u is None:
                    installed = r.device.driver_version or "driver version unknown"
                    return f"{installed} · " + {QUEUED: "waiting to look for updates", SCANNING: "looking for updates…",
                                                NOT_CHECKED: "not checked"}.get(r.phase, "no newer driver found")
                return f"{u.installed} → {u.available} · {u.source}"
            if role == Qt.ToolTipRole:
                ids = ", ".join(h for h in r.device.hardware_ids if not h.startswith("raw:"))[:200]
                return f"{r.device.name}\n{ids}" if ids else r.device.name
        elif col == COL_STATUS:
            text, kind = vf.row_status(u, r.outcome, r.phase)
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
            if role == HelpRole:                   # (?) opens the itemised checks with every reason
                return lvl in (vf.PARTIAL, vf.NONE)
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
