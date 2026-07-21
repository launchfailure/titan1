"""Native Qt widgets for the Titan forensic workbench dashboard."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Iterable

from PySide6.QtCore import QPoint, Qt, QTimer, Signal
from PySide6.QtGui import QDragEnterEvent, QDropEvent, QMouseEvent
from PySide6.QtWidgets import (
    QAbstractItemView,
    QButtonGroup,
    QDialog,
    QFrame,
    QHeaderView,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QLayout,
    QListWidget,
    QListWidgetItem,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QTabWidget,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from titan_decoder.workbench_ui.models import AnalysisSnapshot, WorkbenchState
from titan_decoder.workbench_ui.presenters import (
    decoded_text,
    detections_text,
    hex_preview,
    iocs_text,
    strings_text,
)

from .icons import asset_pixmap, icon, pixmap
from .sample_archive import SampleRecord


def _label(
    text: str = "",
    object_name: str | None = None,
    *,
    alignment: Qt.AlignmentFlag | None = None,
) -> QLabel:
    value = QLabel(text)
    if object_name:
        value.setObjectName(object_name)
    if alignment is not None:
        value.setAlignment(alignment)
    return value


def _clear_layout(layout: QLayout) -> None:
    while layout.count():
        item = layout.takeAt(0)
        if item is None:
            continue
        widget = item.widget()
        if widget is not None:
            widget.deleteLater()
            continue
        child_layout = item.layout()
        if child_layout is not None:
            _clear_layout(child_layout)


class Panel(QFrame):
    """A bordered dashboard panel with a fixed title rail."""

    def __init__(self, title: str, parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("panel")
        self.panel_layout = QVBoxLayout(self)
        self.panel_layout.setContentsMargins(0, 0, 0, 0)
        self.panel_layout.setSpacing(0)
        self.header = _title_rail(
            title,
            frame_object="panelHeader",
            label_object="panelTitle",
            height=36,
            left_margin=12,
        )
        self.panel_layout.addWidget(self.header)


def _title_rail(
    title: str,
    *,
    frame_object: str = "sectionHeader",
    label_object: str = "summaryTitle",
    height: int = 32,
    left_margin: int = 12,
) -> QFrame:
    """Create a full-width title rail separated from the content beneath it."""
    rail = QFrame()
    rail.setObjectName(frame_object)
    rail.setFixedHeight(height)
    layout = QHBoxLayout(rail)
    layout.setContentsMargins(left_margin, 0, 10, 0)
    layout.setSpacing(0)
    layout.addWidget(_label(title, label_object))
    return rail


class TitanMultilineDialog(QDialog):
    """Titan-owned multiline input dialog with no native light-theme chrome."""

    def __init__(
        self,
        parent: QWidget,
        title: str,
        prompt: str,
        *,
        action_text: str = "Analyze",
    ):
        super().__init__(parent)
        self.setObjectName("titanInputDialog")
        self.setWindowTitle(title)
        self.setWindowFlags(
            Qt.WindowType.Dialog
            | Qt.WindowType.FramelessWindowHint
            | Qt.WindowType.WindowSystemMenuHint
        )
        self.setModal(True)
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setFixedSize(520, 382)

        shell = QVBoxLayout(self)
        shell.setContentsMargins(0, 0, 0, 0)
        shell.setSpacing(0)

        header = QFrame()
        header.setObjectName("dialogHeader")
        header.setFixedHeight(46)
        header_row = QHBoxLayout(header)
        header_row.setContentsMargins(14, 0, 9, 0)
        header_row.setSpacing(9)
        mark = _label(alignment=Qt.AlignmentFlag.AlignCenter)
        mark.setPixmap(pixmap("shield", size=25))
        mark.setFixedSize(27, 31)
        header_row.addWidget(mark)
        header_row.addWidget(_label(title, "dialogTitle"), 1)
        close_button = QPushButton()
        close_button.setObjectName("dialogCloseButton")
        close_button.setIcon(icon("close", "#ff6455"))
        close_button.clicked.connect(self.reject)
        header_row.addWidget(close_button)
        shell.addWidget(header)

        body = QWidget()
        body.setObjectName("dialogBody")
        body_layout = QVBoxLayout(body)
        body_layout.setContentsMargins(18, 16, 18, 17)
        body_layout.setSpacing(11)
        body_layout.addWidget(_label(prompt, "dialogPrompt"))
        self.editor = QPlainTextEdit()
        self.editor.setObjectName("dialogEditor")
        self.editor.setPlaceholderText("Paste evidence here…")
        body_layout.addWidget(self.editor, 1)

        actions = QHBoxLayout()
        actions.setSpacing(9)
        actions.addStretch(1)
        cancel_button = QPushButton("Cancel")
        cancel_button.setObjectName("dialogSecondaryButton")
        cancel_button.clicked.connect(self.reject)
        actions.addWidget(cancel_button)
        self.action_button = QPushButton(action_text)
        self.action_button.setObjectName("dialogPrimaryButton")
        self.action_button.setDefault(True)
        self.action_button.clicked.connect(self.accept)
        actions.addWidget(self.action_button)
        body_layout.addLayout(actions)
        shell.addWidget(body, 1)

    @classmethod
    def get_text(
        cls,
        parent: QWidget,
        title: str,
        prompt: str,
        *,
        action_text: str = "Analyze",
    ) -> tuple[str, bool]:
        dialog = cls(parent, title, prompt, action_text=action_text)
        dialog.editor.setFocus()
        accepted = dialog.exec() == QDialog.DialogCode.Accepted
        return dialog.editor.toPlainText(), accepted


class TitanTextDialog(QDialog):
    """Titan-styled read-only workspace dialog for secondary tools and reports."""

    def __init__(
        self,
        parent: QWidget,
        title: str,
        summary: str,
        content: str,
    ):
        super().__init__(parent)
        self.setObjectName("titanToolDialog")
        self.setWindowTitle(title)
        self.setWindowFlags(
            Qt.WindowType.Dialog
            | Qt.WindowType.FramelessWindowHint
            | Qt.WindowType.WindowSystemMenuHint
        )
        self.setModal(True)
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setFixedSize(760, 520)

        shell = QVBoxLayout(self)
        shell.setContentsMargins(0, 0, 0, 0)
        shell.setSpacing(0)

        header = QFrame()
        header.setObjectName("dialogHeader")
        header.setFixedHeight(46)
        header_row = QHBoxLayout(header)
        header_row.setContentsMargins(14, 0, 9, 0)
        header_row.setSpacing(9)
        mark = _label(alignment=Qt.AlignmentFlag.AlignCenter)
        mark.setPixmap(pixmap("shield", size=25))
        mark.setFixedSize(27, 31)
        header_row.addWidget(mark)
        header_row.addWidget(_label(title.upper(), "dialogTitle"), 1)
        close_button = QPushButton()
        close_button.setObjectName("dialogCloseButton")
        close_button.setIcon(icon("close", "#ff6455"))
        close_button.clicked.connect(self.reject)
        header_row.addWidget(close_button)
        shell.addWidget(header)

        body = QWidget()
        body.setObjectName("dialogBody")
        body_layout = QVBoxLayout(body)
        body_layout.setContentsMargins(18, 16, 18, 17)
        body_layout.setSpacing(12)
        prompt = _label(summary, "dialogPrompt")
        prompt.setWordWrap(True)
        body_layout.addWidget(prompt)
        self.viewer = QPlainTextEdit()
        self.viewer.setObjectName("toolViewer")
        self.viewer.setReadOnly(True)
        self.viewer.setPlainText(content)
        body_layout.addWidget(self.viewer, 1)
        actions = QHBoxLayout()
        actions.addStretch(1)
        close_action = QPushButton("Close")
        close_action.setObjectName("dialogPrimaryButton")
        close_action.setDefault(True)
        close_action.clicked.connect(self.accept)
        actions.addWidget(close_action)
        body_layout.addLayout(actions)
        shell.addWidget(body, 1)


class RecentSamplesDialog(QDialog):
    """Persistent archive browser used by the Recent Samples quick action."""

    open_requested = Signal(str)
    save_requested = Signal(str)
    delete_requested = Signal(str)

    def __init__(self, parent: QWidget, records: list[SampleRecord]):
        super().__init__(parent)
        self.setObjectName("recentSamplesDialog")
        self.setWindowTitle("Recent Samples")
        self.setWindowFlags(
            Qt.WindowType.Dialog
            | Qt.WindowType.FramelessWindowHint
            | Qt.WindowType.WindowSystemMenuHint
        )
        self.setModal(True)
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setFixedSize(820, 540)

        shell = QVBoxLayout(self)
        shell.setContentsMargins(0, 0, 0, 0)
        shell.setSpacing(0)
        header = QFrame()
        header.setObjectName("dialogHeader")
        header.setFixedHeight(46)
        header_row = QHBoxLayout(header)
        header_row.setContentsMargins(14, 0, 9, 0)
        header_row.setSpacing(9)
        mark = _label(alignment=Qt.AlignmentFlag.AlignCenter)
        mark.setPixmap(pixmap("shield", size=25))
        mark.setFixedSize(27, 31)
        header_row.addWidget(mark)
        header_row.addWidget(_label("RECENT SAMPLES", "dialogTitle"), 1)
        close_button = QPushButton()
        close_button.setObjectName("dialogCloseButton")
        close_button.setIcon(icon("close", "#ff6455"))
        close_button.clicked.connect(self.reject)
        header_row.addWidget(close_button)
        shell.addWidget(header)

        body = QWidget()
        body.setObjectName("dialogBody")
        body_layout = QVBoxLayout(body)
        body_layout.setContentsMargins(16, 14, 16, 16)
        body_layout.setSpacing(10)
        body_layout.addWidget(
            _label(
                "Archived samples remain available here even after removal from Latest Results.",
                "dialogPrompt",
            )
        )
        self.samples = QTreeWidget()
        self.samples.setObjectName("recentSamplesList")
        self.samples.setColumnCount(4)
        self.samples.setHeaderLabels(("FILE", "SIZE", "ANALYZED", "STATE"))
        self.samples.setRootIsDecorated(False)
        self.samples.setAlternatingRowColors(True)
        self.samples.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.samples.setColumnWidth(0, 310)
        self.samples.setColumnWidth(1, 90)
        self.samples.setColumnWidth(2, 190)
        self.samples.header().setStretchLastSection(True)
        self.samples.itemSelectionChanged.connect(self._selection_changed)
        self.samples.itemDoubleClicked.connect(lambda *_args: self._open_selected())
        body_layout.addWidget(self.samples, 1)

        actions = QHBoxLayout()
        actions.setSpacing(9)
        self.delete_button = QPushButton("Delete Permanently")
        self.delete_button.setObjectName("recentDeleteButton")
        self.delete_button.clicked.connect(self._delete_selected)
        actions.addWidget(self.delete_button)
        actions.addStretch(1)
        self.save_button = QPushButton("Save Copy")
        self.save_button.setObjectName("dialogSecondaryButton")
        self.save_button.clicked.connect(self._save_selected)
        actions.addWidget(self.save_button)
        cancel_button = QPushButton("Close")
        cancel_button.setObjectName("dialogSecondaryButton")
        cancel_button.clicked.connect(self.reject)
        actions.addWidget(cancel_button)
        self.open_button = QPushButton("Open Sample")
        self.open_button.setObjectName("dialogPrimaryButton")
        self.open_button.clicked.connect(self._open_selected)
        actions.addWidget(self.open_button)
        body_layout.addLayout(actions)
        shell.addWidget(body, 1)
        self.set_records(records)

    def set_records(self, records: list[SampleRecord]) -> None:
        selected = self.selected_id()
        self.samples.clear()
        for record in records:
            size = f"{record.size / 1024:.1f} KB"
            state = "In Latest" if record.visible_in_latest else "Archived"
            item = QTreeWidgetItem((record.name, size, record.analyzed_label, state))
            item.setData(0, Qt.ItemDataRole.UserRole, record.id)
            detail = record.source_path or record.sha256 or "Saved Titan analysis"
            item.setToolTip(0, detail)
            self.samples.addTopLevelItem(item)
            if record.id == selected:
                self.samples.setCurrentItem(item)
        if self.samples.currentItem() is None and self.samples.topLevelItemCount():
            first_item = self.samples.topLevelItem(0)
            if first_item is not None:
                self.samples.setCurrentItem(first_item)
        self._selection_changed()

    def selected_id(self) -> str | None:
        item = self.samples.currentItem()
        return str(item.data(0, Qt.ItemDataRole.UserRole)) if item is not None else None

    def _selection_changed(self) -> None:
        enabled = self.selected_id() is not None
        self.open_button.setEnabled(enabled)
        self.save_button.setEnabled(enabled)
        self.delete_button.setEnabled(enabled)

    def _open_selected(self) -> None:
        sample_id = self.selected_id()
        if sample_id:
            self.open_requested.emit(sample_id)

    def _save_selected(self) -> None:
        sample_id = self.selected_id()
        if sample_id:
            self.save_requested.emit(sample_id)

    def _delete_selected(self) -> None:
        sample_id = self.selected_id()
        if sample_id:
            self.delete_requested.emit(sample_id)


class WorkbenchHeader(QFrame):
    profile_requested = Signal()
    network_requested = Signal()
    aggressive_requested = Signal()

    def __init__(
        self,
        state: WorkbenchState,
        version: str,
        session_id: str,
        parent: QWidget | None = None,
    ):
        super().__init__(parent)
        self.state = state
        self.session_id = session_id
        self._drag_origin: QPoint | None = None
        self.setObjectName("header")
        self.setFixedHeight(48)

        row = QHBoxLayout(self)
        row.setContentsMargins(22, 0, 24, 0)
        row.setSpacing(10)

        shield = _label(alignment=Qt.AlignmentFlag.AlignCenter)
        shield.setPixmap(pixmap("shield", "#25b7ff", size=43))
        shield.setFixedSize(48, 46)
        row.addWidget(shield)

        self.title_label = _label("TITAN FORENSIC WORKBENCH", "appTitle")
        self.title_label.setFixedWidth(370)
        row.addWidget(self.title_label)
        version_label = _label(f"v{version}", "appVersion")
        version_label.setFixedWidth(54)
        row.addWidget(version_label)
        # The Windows font backend needs more room for the final "CH". Keep
        # downstream controls fixed by taking the added width from this spacer.
        row.addSpacing(26)

        self.profile_chip = QPushButton()
        self.profile_chip.setObjectName("chipGreen")
        self.profile_chip.setFixedWidth(126)
        self.profile_chip.setToolTip("Click to cycle FAST, FULL, and SAFE profiles")
        self.profile_chip.clicked.connect(self.profile_requested.emit)
        self.network_chip = QPushButton()
        self.network_chip.setObjectName("chipBlue")
        self.network_chip.setFixedWidth(154)
        self.network_chip.setToolTip(
            "Click to enable or disable analysis network access"
        )
        self.network_chip.clicked.connect(self.network_requested.emit)
        self.aggressive_chip = QPushButton()
        self.aggressive_chip.setObjectName("chipYellow")
        self.aggressive_chip.setFixedWidth(145)
        self.aggressive_chip.setToolTip("Click to toggle aggressive decoder coverage")
        self.aggressive_chip.clicked.connect(self.aggressive_requested.emit)
        row.addWidget(self.profile_chip)
        row.addSpacing(6)
        row.addWidget(self.network_chip)
        row.addSpacing(6)
        row.addWidget(self.aggressive_chip)
        row.addStretch(1)

        self.clock = _label(
            object_name="sessionClock",
            alignment=Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
        )
        self.clock.setMinimumWidth(252)
        row.addWidget(self.clock)
        row.addSpacing(8)

        self.minimize_button = self._window_button("minus", "#91a2b3")
        self.maximize_button = self._window_button("square", "#91a2b3")
        self.close_button = self._window_button("close", "#ff6455", close=True)
        row.addWidget(self.minimize_button)
        row.addSpacing(3)
        row.addWidget(self.maximize_button)
        row.addSpacing(3)
        row.addWidget(self.close_button)

        self.refresh_state(state)
        self._refresh_clock()
        timer = QTimer(self)
        timer.timeout.connect(self._refresh_clock)
        timer.start(1000)

    @staticmethod
    def _window_button(name: str, color: str, *, close: bool = False) -> QPushButton:
        button = QPushButton()
        button.setObjectName("closeButton" if close else "windowButton")
        button.setIcon(icon(name, color))
        button.setIconSize(pixmap(name, color, size=15).size())
        return button

    def refresh_state(self, state: WorkbenchState) -> None:
        self.state = state
        self.profile_chip.setText(f"PROFILE:  {state.profile.upper()}")
        self.network_chip.setText(
            f"NETWORK:  {'OFFLINE' if state.offline else 'ONLINE'}"
        )
        self.aggressive_chip.setText(
            f"AGGRESSIVE:  {'ON' if state.aggressive else 'OFF'}"
        )

    def _refresh_clock(self) -> None:
        self.clock.setText(
            f"SESSION: {self.session_id}    │    {datetime.now():%H:%M:%S}"
        )

    def mousePressEvent(self, event: QMouseEvent) -> None:  # noqa: N802
        if event.button() == Qt.MouseButton.LeftButton:
            self._drag_origin = event.globalPosition().toPoint() - self.window().pos()
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event: QMouseEvent) -> None:  # noqa: N802
        if (
            self._drag_origin is not None
            and event.buttons() & Qt.MouseButton.LeftButton
        ):
            self.window().move(event.globalPosition().toPoint() - self._drag_origin)
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event: QMouseEvent) -> None:  # noqa: N802
        self._drag_origin = None
        super().mouseReleaseEvent(event)


class NavigationColumn(QWidget):
    route_selected = Signal(str)

    _NAVIGATION = (
        ("home", "Dashboard", "dashboard"),
        ("search", "Analyze Input", "investigation"),
        ("code", "Decoder Workbench", "decoders"),
        ("folder", "Reports Browser", "reports"),
        ("chip", "Memory Analysis", "memory"),
        ("file", "File Analysis", "file-analysis"),
        ("graph", "Correlation Engine", "correlation"),
        ("puzzle", "Plugins", "plugins"),
        ("target", "IOC Manager", "iocs"),
        ("settings", "Settings", "settings"),
        ("book", "Help & Docs", "help"),
    )
    _SHORTCUTS = (
        ("H", "Dashboard", "dashboard"),
        ("A", "Analyze Input", "investigation"),
        ("D", "Decoder Workbench", "decoders"),
        ("R", "Reports Browser", "reports"),
        ("P", "Plugins", "plugins"),
        ("S", "Settings", "settings"),
        ("?", "Help", "help"),
        ("Ctrl+L", "Refresh", "refresh"),
        ("Q", "Quit", "quit"),
    )

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setFixedWidth(224)
        column = QVBoxLayout(self)
        column.setContentsMargins(0, 0, 0, 0)
        column.setSpacing(0)

        nav = Panel("NAVIGATION")
        nav.setObjectName("sideCard")
        nav.setFixedHeight(439)
        nav_body = QWidget()
        nav_layout = QVBoxLayout(nav_body)
        nav_layout.setContentsMargins(0, 4, 0, 4)
        nav_layout.setSpacing(0)
        group = QButtonGroup(self)
        group.setExclusive(True)
        self.nav_buttons: dict[str, QPushButton] = {}
        for offset, (icon_name, label, route) in enumerate(self._NAVIGATION):
            button = QPushButton(f"  {label.replace('&', '&&')}")
            button.setObjectName("navButton")
            button.setCheckable(True)
            button.setIcon(icon(icon_name, "#a8b8c9"))
            button.setIconSize(pixmap(icon_name, size=18).size())
            button.clicked.connect(
                lambda _checked=False, value=route: self.route_selected.emit(value)
            )
            if offset == 0:
                button.setChecked(True)
            group.addButton(button)
            self.nav_buttons[route] = button
            nav_layout.addWidget(button)
        nav.panel_layout.addWidget(nav_body)
        column.addWidget(nav)
        column.addSpacing(14)

        shortcuts = Panel("SHORTCUTS")
        shortcuts.setObjectName("sideCard")
        shortcuts.setFixedHeight(296)
        shortcut_body = QWidget()
        shortcut_layout = QVBoxLayout(shortcut_body)
        shortcut_layout.setContentsMargins(14, 4, 12, 2)
        shortcut_layout.setSpacing(0)
        self.shortcut_buttons: dict[str, QPushButton] = {}
        self.shortcut_key_labels: dict[str, QLabel] = {}
        self.shortcut_text_labels: dict[str, QLabel] = {}
        for key, label, route in self._SHORTCUTS:
            line_widget = QPushButton()
            line_widget.setObjectName("shortcutRowButton")
            line_widget.setFixedHeight(27)
            line_widget.clicked.connect(
                lambda _checked=False, value=route: self.route_selected.emit(value)
            )
            line = QHBoxLayout(line_widget)
            line.setContentsMargins(0, 0, 0, 0)
            line.setSpacing(10 if key == "Ctrl+L" else 14)
            key_label = _label(key, "shortcutKey")
            key_label.setFixedWidth(40 if key == "Ctrl+L" else 25)
            key_label.setAttribute(
                Qt.WidgetAttribute.WA_TransparentForMouseEvents, True
            )
            line.addWidget(key_label)
            text_label = _label(label, "shortcutText")
            text_label.setAttribute(
                Qt.WidgetAttribute.WA_TransparentForMouseEvents, True
            )
            line.addWidget(text_label, 1)
            self.shortcut_key_labels[route] = key_label
            self.shortcut_text_labels[route] = text_label
            self.shortcut_buttons[route] = line_widget
            shortcut_layout.addWidget(line_widget)
        shortcut_layout.addStretch(1)
        shortcuts.panel_layout.addWidget(shortcut_body)
        column.addWidget(shortcuts)
        column.addSpacing(10)

        brand = QFrame()
        brand.setObjectName("brandCard")
        brand.setFixedHeight(147)
        brand_logo = _label(
            alignment=Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter
        )
        brand_logo.setParent(brand)
        brand_logo.setPixmap(asset_pixmap("titan-wordmark.png", width=183))
        brand_logo.setGeometry(8, 19, 206, 73)
        brand_tag = _label(
            "DETERMINISTIC ANALYSIS",
            "brandTag",
            alignment=Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop,
        )
        brand_tag.setParent(brand)
        brand_tag.setGeometry(9, 89, 209, 18)
        brand_tag.setContentsMargins(12, 0, 0, 0)
        brand_power = _label(
            "POWERED BY TITAN ENGINE",
            "brandPower",
            alignment=Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop,
        )
        brand_power.setParent(brand)
        brand_power.setGeometry(9, 113, 209, 18)
        brand_power.setContentsMargins(12, 4, 0, 0)
        column.addWidget(brand)


class DropZone(QFrame):
    path_dropped = Signal(str)
    clicked = Signal()

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("dropZone")
        self.setProperty("dragActive", False)
        self.setAcceptDrops(True)
        self.setToolTip("Click to select evidence")
        body = QVBoxLayout(self)
        body.setContentsMargins(16, 28, 16, 28)
        body.setSpacing(8)
        body.addStretch(1)
        upload = _label(alignment=Qt.AlignmentFlag.AlignCenter)
        upload.setPixmap(pixmap("upload", "#a8b9c9", size=57))
        body.addWidget(upload)
        body.addSpacing(5)
        body.addWidget(
            _label(
                "DROP FILES HERE", "dropTitle", alignment=Qt.AlignmentFlag.AlignCenter
            )
        )
        hint = QHBoxLayout()
        hint.setSpacing(4)
        hint.addStretch(1)
        hint.addWidget(_label("click here or press", "dropHint"))
        hint.addWidget(_label("[A]", "dropHintAccent"))
        hint.addWidget(_label("to analyze input", "dropHint"))
        hint.addStretch(1)
        body.addLayout(hint)
        body.addStretch(3)

    def _set_drag_active(self, active: bool) -> None:
        self.setProperty("dragActive", active)
        self.style().unpolish(self)
        self.style().polish(self)

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:  # noqa: N802
        if event.mimeData().hasUrls() or event.mimeData().hasText():
            self._set_drag_active(True)
            event.acceptProposedAction()

    def dragLeaveEvent(self, event) -> None:  # noqa: N802, ANN001
        self._set_drag_active(False)
        super().dragLeaveEvent(event)

    def dropEvent(self, event: QDropEvent) -> None:  # noqa: N802
        self._set_drag_active(False)
        candidates = [
            url.toLocalFile() or url.toString() for url in event.mimeData().urls()
        ]
        if event.mimeData().hasText():
            candidates.extend(event.mimeData().text().splitlines())
        if candidates:
            self.path_dropped.emit(candidates[0])
            event.acceptProposedAction()

    def mousePressEvent(self, event: QMouseEvent) -> None:  # noqa: N802
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit()
        super().mousePressEvent(event)


class QuickAction(QFrame):
    clicked = Signal()

    def __init__(self, icon_name: str, title: str, tone: str):
        super().__init__()
        self.setObjectName("quickRow")
        colors = {
            "Violet": "#ce72ff",
            "Blue": "#58c7ff",
            "Green": "#59df78",
            "Yellow": "#f0cb38",
        }
        row = QHBoxLayout(self)
        row.setContentsMargins(13, 7, 10, 7)
        row.setSpacing(11)
        icon_box = _label(
            object_name=f"iconBox{tone}",
            alignment=Qt.AlignmentFlag.AlignCenter,
        )
        icon_box.setPixmap(pixmap(icon_name, colors[tone], size=19))
        row.addWidget(icon_box)
        row.addWidget(_label(title, "quickText"), 1)
        row.addWidget(_label("›", "quickChevron"))

    def mousePressEvent(self, event: QMouseEvent) -> None:  # noqa: N802
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit()
        super().mousePressEvent(event)


class InvestigationPanel(Panel):
    path_requested = Signal()
    path_dropped = Signal(str)
    paste_requested = Signal()
    hex_requested = Signal()
    recent_requested = Signal()

    def __init__(self, parent: QWidget | None = None):
        super().__init__("INVESTIGATION WORKSPACE", parent)
        self.setFixedHeight(313)
        body = QWidget()
        row = QHBoxLayout(body)
        row.setContentsMargins(21, 16, 19, 20)
        row.setSpacing(22)

        self.drop_zone = DropZone()
        self.drop_zone.setFixedWidth(493)
        self.drop_zone.path_dropped.connect(self.path_dropped)
        self.drop_zone.clicked.connect(self.path_requested)
        row.addWidget(self.drop_zone)

        quick = QFrame()
        quick.setObjectName("innerCard")
        quick.setFixedWidth(301)
        quick_layout = QVBoxLayout(quick)
        quick_layout.setContentsMargins(0, 0, 0, 0)
        quick_layout.setSpacing(0)
        quick_layout.addWidget(
            _title_rail(
                "QUICK START",
                frame_object="quickHeader",
                label_object="subTitle",
                height=42,
                left_margin=13,
            )
        )
        actions = (
            ("clipboard", "Paste text / data", "Violet", self.paste_requested),
            ("hash", "Enter hex string", "Blue", self.hex_requested),
            ("folder", "Load from file", "Green", self.path_requested),
            ("clock", "Recent samples", "Yellow", self.recent_requested),
        )
        for icon_name, title, tone, signal in actions:
            button = QuickAction(icon_name, title, tone)
            button.clicked.connect(signal)
            quick_layout.addWidget(button)
        quick_layout.addStretch(1)
        row.addWidget(quick)
        self.panel_layout.addWidget(body)


class MetricCard(QFrame):
    def __init__(self, title: str, tone: str):
        super().__init__()
        self.setObjectName(f"metric{tone}")
        shell = QVBoxLayout(self)
        shell.setContentsMargins(0, 0, 0, 0)
        shell.setSpacing(0)
        shell.addWidget(
            _title_rail(
                title,
                frame_object=f"metricHeader{tone}",
                label_object=f"metricTitle{tone}",
                height=36,
                left_margin=16,
            )
        )
        body = QWidget()
        self.body = QVBoxLayout(body)
        self.body.setContentsMargins(16, 7, 16, 11)
        self.body.setSpacing(6)
        shell.addWidget(body, 1)

    def set_rows(self, rows: Iterable[tuple[str, str]]) -> None:
        _clear_layout(self.body)
        for name, value in rows:
            line = QHBoxLayout()
            line.setSpacing(6)
            line.addWidget(_label(name, "metricName"))
            line.addStretch(1)
            line.addWidget(
                _label(value, "metricValue", alignment=Qt.AlignmentFlag.AlignRight)
            )
            self.body.addLayout(line)
        self.body.addStretch(1)

    def set_resource_rows(self, metrics: dict[str, str]) -> None:
        _clear_layout(self.body)
        for name, key in (
            ("CPU", "cpu_percent"),
            ("Memory", "memory_percent"),
            ("Disk I/O", "disk_percent"),
        ):
            try:
                value = int(float(metrics.get(key, "0")))
            except ValueError:
                value = 0
            line = QHBoxLayout()
            line.setSpacing(8)
            line.addWidget(_label(name, "metricName"))
            bar = QProgressBar()
            bar.setRange(0, 100)
            bar.setValue(value)
            bar.setTextVisible(False)
            line.addWidget(bar, 1)
            line.addWidget(
                _label(
                    f"{value}%", "metricValue", alignment=Qt.AlignmentFlag.AlignRight
                )
            )
            self.body.addLayout(line)
        workers = QHBoxLayout()
        workers.addWidget(_label("Workers", "metricName"))
        workers.addStretch(1)
        workers.addWidget(_label(f"{metrics.get('workers', '1')}/8", "metricValue"))
        self.body.addLayout(workers)
        self.body.addStretch(1)


class StatusCards(QWidget):
    def __init__(
        self,
        state: WorkbenchState,
        *,
        engine_version: str,
        session_id: str,
        started_at: str,
        decoder_count: int,
        plugin_count: int,
        metrics: dict[str, str],
        snapshot: AnalysisSnapshot,
    ):
        super().__init__()
        self.setFixedHeight(184)
        self.state = state
        self.engine_version = engine_version
        self.session_id = session_id
        self.started_at = started_at
        row = QHBoxLayout(self)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(14)
        self.session = MetricCard("SESSION INFO", "Violet")
        self.system = MetricCard("SYSTEM STATUS", "Blue")
        self.engine = MetricCard("ENGINE STATUS", "Green")
        self.resources = MetricCard("RESOURCE USAGE", "Yellow")
        self.session.setFixedWidth(201)
        self.system.setFixedWidth(202)
        self.engine.setFixedWidth(202)
        row.addWidget(self.session)
        row.addWidget(self.system)
        row.addWidget(self.engine)
        row.addWidget(self.resources, 1)
        self.system.set_rows(
            (
                ("Decoders", str(decoder_count)),
                ("Plugins", str(plugin_count)),
                ("Rules", "312"),
                ("Signatures", "18,746"),
                ("YARA Rules", "1,284"),
            )
        )
        self.resources.set_resource_rows(metrics)
        self.refresh_state(state)
        self.refresh_snapshot(snapshot)

    def refresh_state(self, state: WorkbenchState) -> None:
        self.state = state
        self.engine.set_rows(
            (
                ("Engine", f"v{self.engine_version}"),
                ("Profile", state.profile.upper()),
                ("Aggressive", "ON" if state.aggressive else "OFF"),
                ("Network", "OFFLINE" if state.offline else "ONLINE"),
                ("Uptime", "00:04:21"),
            )
        )

    def refresh_snapshot(self, snapshot: AnalysisSnapshot) -> None:
        self.session.set_rows(
            (
                ("ID", self.session_id),
                ("Started", self.started_at),
                ("Artifacts", str(snapshot.artifact_count)),
                ("Analyses", "1" if snapshot.report else "0"),
                ("Decodes", str(snapshot.decode_count)),
            )
        )


class SummaryGrid(QWidget):
    def __init__(self):
        super().__init__()
        self.content_layout = QVBoxLayout(self)
        self.content_layout.setContentsMargins(10, 10, 10, 10)
        self.content_layout.setSpacing(10)

    @staticmethod
    def _data_card(title: str, rows: Iterable[tuple[str, str, str]]) -> QFrame:
        card = QFrame()
        card.setObjectName("summaryCard")
        shell = QVBoxLayout(card)
        shell.setContentsMargins(0, 0, 0, 0)
        shell.setSpacing(0)
        shell.addWidget(_title_rail(title, height=31, left_margin=12))
        body = QWidget()
        column = QVBoxLayout(body)
        column.setContentsMargins(12, 7, 12, 10)
        column.setSpacing(5)
        for name, value, value_style in rows:
            line = QHBoxLayout()
            line.addWidget(_label(name, "summaryName"))
            line.addStretch(1)
            line.addWidget(_label(value, value_style))
            column.addLayout(line)
        column.addStretch(1)
        shell.addWidget(body, 1)
        return card

    def refresh(self, snapshot: AnalysisSnapshot, state: WorkbenchState) -> None:
        _clear_layout(self.content_layout)
        grid = QHBoxLayout()
        grid.setSpacing(10)
        status = str(snapshot.analysis_outcome.get("status") or "waiting")
        status_label = {
            "decoded": "✓ Completed",
            "analyzed": "✓ Completed",
            "partial_decode": "Partial Decode",
            "unrecognized": "Unrecognized",
        }.get(status, status.replace("_", " ").title())
        grid.addWidget(
            self._data_card(
                "ANALYSIS OVERVIEW",
                (
                    ("Status", status_label, "summaryGood"),
                    ("Profile", state.profile.upper(), "summaryValue"),
                    ("Duration", f"{snapshot.duration_seconds:.2f}s", "summaryValue"),
                    ("Decoders Used", str(snapshot.decode_count), "summaryValue"),
                    ("Artifacts Found", str(snapshot.artifact_count), "summaryValue"),
                    ("IOC Extracted", str(snapshot.ioc_count), "summaryValue"),
                ),
            ),
            1,
        )
        iocs = snapshot.iocs
        public_ips = len(iocs.get("ipv4_public", [])) + len(iocs.get("ipv4", []))
        high_entropy = sum(
            float(node.get("entropy", 0) or 0) >= 7.5 for node in snapshot.nodes
        )
        grid.addWidget(
            self._data_card(
                "TOP FINDINGS",
                (
                    (
                        "<span style='color:#df69ba'>◆</span>  URLs",
                        str(len(iocs.get("urls", []))),
                        "summaryValue",
                    ),
                    (
                        "<span style='color:#ff6b2f'>◆</span>  IP Addresses",
                        str(public_ips),
                        "summaryValue",
                    ),
                    (
                        "<span style='color:#ffbb20'>●</span>  Email Addresses",
                        str(len(iocs.get("emails", []))),
                        "summaryValue",
                    ),
                    (
                        "<span style='color:#f4d02b'>●</span>  File Hashes",
                        str(len(iocs.get("hashes", []))),
                        "summaryValue",
                    ),
                    (
                        "<span style='color:#5ccdd0'>●</span>  Interesting Strings",
                        str(len(snapshot.strings)),
                        "summaryValue",
                    ),
                    (
                        "<span style='color:#8f9cff'>◆</span>  Entropy High Regions",
                        str(high_entropy),
                        "summaryValue",
                    ),
                ),
            ),
            1,
        )
        self.content_layout.addLayout(grid, 1)

        highlights = QFrame()
        highlights.setObjectName("summaryCard")
        highlight_column = QVBoxLayout(highlights)
        highlight_column.setContentsMargins(0, 0, 0, 0)
        highlight_column.setSpacing(0)
        highlight_column.addWidget(
            _title_rail("DETECTION HIGHLIGHTS", height=31, left_margin=12)
        )
        highlight_body = QWidget()
        highlight_body_layout = QVBoxLayout(highlight_body)
        highlight_body_layout.setContentsMargins(12, 7, 12, 9)
        highlight_body_layout.setSpacing(0)
        chips = QHBoxLayout()
        chips.setSpacing(7)
        values: list[tuple[str, str]] = []
        decoders: list[str] = []
        for node in snapshot.nodes:
            decoder = str(node.get("decoder_used") or "")
            if decoder and decoder not in decoders:
                decoders.append(decoder)
        values.extend((f"{decoder} Data", "highlightGreen") for decoder in decoders[:1])
        for item in snapshot.detections:
            label = str(item.get("name") or item.get("rule_id") or "Detection")
            lowered = label.lower()
            style = "highlightOrange"
            if "xor" in lowered:
                style = "highlightYellow"
            elif "url" in lowered:
                style = "highlightBlue"
            elif "hash" in lowered:
                style = "highlightViolet"
            values.append((label, style))
            if len(values) == 5:
                break
        labels = {label.lower() for label, _style in values}
        if high_entropy and "high entropy" not in labels:
            values.append(("High Entropy", "highlightOrange"))
        if snapshot.ioc_count and not any("url" in label for label in labels):
            values.append(("URL Detected", "highlightBlue"))
        if not values:
            values.append(("Awaiting Analysis", "highlightBlue"))
        for text, style in values[:5]:
            chip = _label(text, style, alignment=Qt.AlignmentFlag.AlignCenter)
            chips.addWidget(chip)
        chips.addStretch(1)
        highlight_body_layout.addLayout(chips)
        highlight_column.addWidget(highlight_body, 1)
        self.content_layout.addWidget(highlights)


class ResultsPanel(Panel):
    sample_selected = Signal(str)
    sample_save_requested = Signal(str)
    sample_remove_requested = Signal(str)

    def __init__(self, snapshot: AnalysisSnapshot, state: WorkbenchState):
        super().__init__("LATEST ANALYSIS RESULTS")
        self.state = state
        body = QWidget()
        row = QHBoxLayout(body)
        row.setContentsMargins(4, 8, 8, 8)
        row.setSpacing(12)

        artifact = QFrame()
        artifact.setObjectName("innerCard")
        artifact.setFixedWidth(281)
        artifact_layout = QVBoxLayout(artifact)
        artifact_layout.setContentsMargins(10, 11, 10, 10)
        artifact_layout.setSpacing(7)
        artifact_top = QHBoxLayout()
        artifact_icon = _label(alignment=Qt.AlignmentFlag.AlignTop)
        artifact_icon.setPixmap(pixmap("document", "#cbd6e0", size=29))
        artifact_icon.setFixedWidth(34)
        artifact_top.addWidget(artifact_icon)
        names = QVBoxLayout()
        names.setSpacing(3)
        self.artifact_name = _label(object_name="artifactName")
        self.artifact_type = _label(object_name="artifactMeta")
        names.addWidget(self.artifact_name)
        names.addWidget(self.artifact_type)
        artifact_top.addLayout(names, 1)
        artifact_layout.addLayout(artifact_top)
        artifact_layout.addWidget(
            _title_rail(
                "PREVIOUS FILES",
                frame_object="subsectionHeader",
                height=27,
                left_margin=8,
            )
        )
        self.history = QListWidget()
        self.history.setObjectName("sampleHistoryList")
        self.history.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.history.itemSelectionChanged.connect(self._history_selection_changed)
        artifact_layout.addWidget(self.history, 1)
        history_actions = QHBoxLayout()
        history_actions.setSpacing(7)
        self.save_sample_button = QPushButton("Save Copy")
        self.save_sample_button.setObjectName("historyActionButton")
        self.save_sample_button.clicked.connect(self._save_selected_sample)
        history_actions.addWidget(self.save_sample_button)
        self.remove_sample_button = QPushButton("Remove")
        self.remove_sample_button.setObjectName("historyRemoveButton")
        self.remove_sample_button.clicked.connect(self._remove_selected_sample)
        history_actions.addWidget(self.remove_sample_button)
        artifact_layout.addLayout(history_actions)
        self._updating_history = False
        row.addWidget(artifact)

        self.tabs = QTabWidget()
        self.summary = SummaryGrid()
        self.detections = self._text_tab()
        self.strings = self._text_tab()
        self.iocs = self._text_tab()
        self.hex_view = self._text_tab()
        self.tabs.addTab(self.summary, "SUMMARY")
        self.tabs.addTab(self.detections, "DETECTIONS (0)")
        self.tabs.addTab(self.strings, "STRINGS (0)")
        self.tabs.addTab(self.iocs, "IOC (0)")
        self.tabs.addTab(self.hex_view, "HEX VIEW")
        row.addWidget(self.tabs, 1)
        self.panel_layout.addWidget(body, 1)
        self.refresh(snapshot, state)

    def selected_sample_id(self) -> str | None:
        item = self.history.currentItem()
        value = item.data(Qt.ItemDataRole.UserRole) if item is not None else None
        return str(value) if value else None

    def refresh_history(
        self,
        records: list[SampleRecord],
        selected_id: str | None = None,
    ) -> None:
        self._updating_history = True
        self.history.clear()
        for record in records:
            suffix = Path(record.name).suffix.lower().lstrip(".") or "data"
            type_name = {"txt": "Text", "json": "JSON"}.get(suffix, suffix.upper())
            item = QListWidgetItem(
                f"{record.name}\n{type_name}  •  {record.size / 1024:.1f} KB  •  "
                f"{record.analyzed_label.split('  ')[-1]}"
            )
            item.setData(Qt.ItemDataRole.UserRole, record.id)
            item.setToolTip(record.source_path or record.sha256 or "Archived analysis")
            self.history.addItem(item)
            if record.id == selected_id:
                self.history.setCurrentItem(item)
        if self.history.count() == 0:
            item = QListWidgetItem("No archived samples yet")
            item.setFlags(Qt.ItemFlag.NoItemFlags)
            self.history.addItem(item)
        self._updating_history = False
        enabled = self.selected_sample_id() is not None
        self.save_sample_button.setEnabled(enabled)
        self.remove_sample_button.setEnabled(enabled)

    def _history_selection_changed(self) -> None:
        sample_id = self.selected_sample_id()
        enabled = sample_id is not None
        self.save_sample_button.setEnabled(enabled)
        self.remove_sample_button.setEnabled(enabled)
        if sample_id and not self._updating_history:
            self.sample_selected.emit(sample_id)

    def _save_selected_sample(self) -> None:
        sample_id = self.selected_sample_id()
        if sample_id:
            self.sample_save_requested.emit(sample_id)

    def _remove_selected_sample(self) -> None:
        sample_id = self.selected_sample_id()
        if sample_id:
            self.sample_remove_requested.emit(sample_id)

    @staticmethod
    def _text_tab() -> QPlainTextEdit:
        view = QPlainTextEdit()
        view.setReadOnly(True)
        view.setFrameShape(QFrame.Shape.NoFrame)
        return view

    def refresh(self, snapshot: AnalysisSnapshot, state: WorkbenchState) -> None:
        self.state = state
        self.artifact_name.setText(snapshot.source_name)
        suffix = Path(snapshot.source_name).suffix.lower().lstrip(".") or "data"
        type_name = (
            {"txt": "Text File"}.get(suffix, f"{suffix.upper()} File")
            if snapshot.report
            else "No sample loaded"
        )
        self.artifact_type.setText(
            f"{type_name}  •  {snapshot.source_size / 1024:.1f} KB  •  "
            f"{datetime.now():%H:%M:%S}"
        )
        self.summary.refresh(snapshot, state)
        self.tabs.setTabText(1, f"DETECTIONS ({len(snapshot.detections)})")
        self.tabs.setTabText(2, f"STRINGS ({len(snapshot.strings)})")
        self.tabs.setTabText(3, f"IOC ({snapshot.ioc_count})")
        self.detections.setPlainText(detections_text(snapshot))
        self.strings.setPlainText(strings_text(snapshot))
        self.iocs.setPlainText(iocs_text(snapshot))
        self.hex_view.setPlainText(
            hex_preview(
                snapshot.decoded_output, empty="No raw decoder output captured."
            )
        )


class DecoderWorkbench(Panel):
    decoder_selected = Signal(int)

    def __init__(self, decoder_rows: list[tuple[int, str, str]]):
        super().__init__("DECODER WORKBENCH")
        self.decoder_rows = decoder_rows
        toolbar = QWidget()
        toolbar.setFixedHeight(54)
        toolbar_layout = QHBoxLayout(toolbar)
        toolbar_layout.setContentsMargins(12, 8, 12, 8)
        toolbar_layout.setSpacing(10)
        self.search = QLineEdit()
        self.search.setPlaceholderText("⌕  Search decoders...")
        self.search.textChanged.connect(self._filter)
        toolbar_layout.addWidget(self.search, 1)
        count = _label(
            f"{len(decoder_rows)} Decoders Available",
            "decoderCount",
            alignment=Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
        )
        count.setFixedWidth(142)
        toolbar_layout.addWidget(count)
        self.panel_layout.addWidget(toolbar)

        list_wrap = QWidget()
        list_layout = QVBoxLayout(list_wrap)
        list_layout.setContentsMargins(12, 0, 12, 8)
        list_layout.setSpacing(8)
        self.list = QTreeWidget()
        self.list.setObjectName("decoderList")
        self.list.setHeaderHidden(True)
        self.list.setColumnCount(3)
        self.list.header().setStretchLastSection(False)
        self.list.setColumnWidth(0, 34)
        self.list.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        self.list.header().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.list.header().setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        self.list.setColumnWidth(2, 48)
        self.list.setRootIsDecorated(False)
        self.list.setUniformRowHeights(True)
        self.list.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.list.currentItemChanged.connect(self._selection_changed)
        list_layout.addWidget(self.list, 1)
        footer = QPushButton(
            "…   View all decoders                                                       ›"
        )
        footer.setObjectName("secondaryButton")
        footer.setFixedHeight(35)
        footer.setStyleSheet("text-align:left; padding-left:10px;")
        list_layout.addWidget(footer)
        self.panel_layout.addWidget(list_wrap, 1)
        self._populate(decoder_rows)

    def _populate(self, rows: list[tuple[int, str, str]]) -> None:
        self.list.clear()
        for index, label, description in rows:
            item = QTreeWidgetItem((f"{index + 1:02d}", label, ""))
            item.setData(0, Qt.ItemDataRole.UserRole, index)
            item.setToolTip(1, description)
            self.list.addTopLevelItem(item)
            indicator = _label(
                "✓  ●" if index == 0 else "●",
                "green",
                alignment=Qt.AlignmentFlag.AlignCenter,
            )
            self.list.setItemWidget(item, 2, indicator)
        if self.list.topLevelItemCount():
            first_item = self.list.topLevelItem(0)
            if first_item is not None:
                self.list.setCurrentItem(first_item)

    def _filter(self, text: str) -> None:
        needle = text.strip().lower()
        rows = [
            row
            for row in self.decoder_rows
            if not needle or needle in row[1].lower() or needle in row[2].lower()
        ]
        self._populate(rows)

    def _selection_changed(self, current: QTreeWidgetItem | None) -> None:
        if current is not None:
            self.decoder_selected.emit(int(current.data(0, Qt.ItemDataRole.UserRole)))


class DecoderDetails(Panel):
    copy_requested = Signal()
    save_requested = Signal()
    run_requested = Signal()

    def __init__(self, label: str, description: str, snapshot: AnalysisSnapshot):
        super().__init__("DECODER DETAILS")
        self.description = QFrame()
        self.description.setObjectName("detailSection")
        description_layout = QVBoxLayout(self.description)
        description_layout.setContentsMargins(14, 10, 14, 10)
        description_layout.setSpacing(4)
        self.decoder_name = _label(object_name="artifactName")
        self.decoder_description = _label(object_name="muted")
        self.decoder_description.setWordWrap(True)
        description_layout.addWidget(self.decoder_name)
        description_layout.addWidget(self.decoder_description)
        self.panel_layout.addWidget(self.description)

        self.input_text, self.input_meta = self._section("INPUT")
        self.output_text, self.output_meta = self._section("OUTPUT")

        status = QWidget()
        status_layout = QVBoxLayout(status)
        status_layout.setContentsMargins(14, 9, 14, 8)
        status_layout.setSpacing(6)
        status_layout.addWidget(_label("STATUS", "sectionTitle"))
        status_line = QHBoxLayout()
        self.status_text = _label(object_name="decoderStatus")
        self.confidence = _label(object_name="muted")
        status_line.addWidget(self.status_text)
        status_line.addStretch(1)
        status_line.addWidget(self.confidence)
        status_layout.addLayout(status_line)
        self.panel_layout.addWidget(status)

        actions = QWidget()
        action_layout = QVBoxLayout(actions)
        action_layout.setContentsMargins(14, 5, 14, 12)
        action_layout.setSpacing(8)
        action_layout.addWidget(_label("ACTIONS", "sectionTitle"))
        buttons = QHBoxLayout()
        buttons.setSpacing(7)
        copy = self._action_button("copy", "Copy Output", "secondaryButton")
        save = self._action_button("save", "Save Output", "secondaryButton")
        run = self._action_button("play", "Run Decoder", "successButton", "#55e177")
        copy.clicked.connect(self.copy_requested)
        save.clicked.connect(self.save_requested)
        run.clicked.connect(self.run_requested)
        buttons.addWidget(copy)
        buttons.addWidget(save)
        buttons.addWidget(run)
        action_layout.addLayout(buttons)
        self.panel_layout.addWidget(actions)
        self.panel_layout.addStretch(1)
        self.refresh_decoder(label, description)
        self.refresh_snapshot(snapshot)

    def _section(self, title: str) -> tuple[QLabel, QLabel]:
        frame = QFrame()
        frame.setObjectName("detailSection")
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(14, 9, 14, 9)
        layout.setSpacing(6)
        layout.addWidget(_label(title, "sectionTitle"))
        text = _label(object_name="detailText")
        text.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        meta = _label(object_name="detailMeta", alignment=Qt.AlignmentFlag.AlignRight)
        layout.addWidget(text)
        layout.addWidget(meta)
        self.panel_layout.addWidget(frame)
        return text, meta

    @staticmethod
    def _action_button(
        icon_name: str, text: str, style: str, color: str = "#a9b8c8"
    ) -> QPushButton:
        button = QPushButton(text)
        button.setObjectName(style)
        button.setIcon(icon(icon_name, color))
        button.setIconSize(pixmap(icon_name, color, size=16).size())
        return button

    def refresh_decoder(self, label: str, description: str) -> None:
        self.decoder_name.setText(label)
        self.decoder_description.setText(description)

    def refresh_snapshot(self, snapshot: AnalysisSnapshot) -> None:
        self.input_text.setText(snapshot.input_preview or snapshot.source_name)
        self.input_meta.setText(f"{snapshot.source_size:,} bytes")
        self.output_text.setText(decoded_text(snapshot))
        self.output_meta.setText(f"{len(snapshot.decoded_output or b''):,} bytes")
        if snapshot.decoder_success is True:
            self.status_text.setText("Successfully Decoded!")
            self._set_status_state("success")
            self.confidence.setText("Confidence: 1.00")
        elif snapshot.decoder_success is False:
            self.status_text.setText("Decode Failed")
            self._set_status_state("failure")
            self.confidence.setText("Confidence: 0.00")
        else:
            self.status_text.setText("Not Running")
            self._set_status_state("inactive")
            self.confidence.setText("Confidence: --")

    def _set_status_state(self, state: str) -> None:
        self.status_text.setProperty("statusState", state)
        style = self.status_text.style()
        style.unpolish(self.status_text)
        style.polish(self.status_text)
        self.status_text.update()


class WorkbenchFooter(QFrame):
    def __init__(self, state: WorkbenchState):
        super().__init__()
        self.setObjectName("footer")
        self.setFixedHeight(42)
        row = QHBoxLayout(self)
        row.setContentsMargins(12, 0, 12, 0)
        row.setSpacing(18)
        self.status = _label("●  Ready", "green")
        self.status.setFixedWidth(160)
        row.addWidget(self.status)
        working = _label(f"Working Directory: {Path.cwd()}", "footerText")
        row.addWidget(working, 1)
        self.mode = _label(object_name="footerText")
        row.addWidget(self.mode)
        row.addWidget(_label("│", "muted"))
        row.addWidget(_label("No updates available", "footerText"))
        row.addWidget(_label("│", "muted"))
        row.addWidget(_label("Press ? for help", "footerText"))
        self.refresh_state(state)

    def refresh_state(self, state: WorkbenchState) -> None:
        self.mode.setText("Offline Mode" if state.offline else "Online Mode")

    def set_activity(self, text: str | None) -> None:
        self.status.setText(f"●  {text}" if text else "●  Ready")
