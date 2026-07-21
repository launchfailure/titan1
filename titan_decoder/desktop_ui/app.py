"""Pixel-layout native desktop workbench for Titan.

Unlike the Textual interface, this window uses pixel geometry and embedded SVG
icons so it can reproduce the approved 1536×1024 layout without terminal-cell
constraints.
"""

from __future__ import annotations

import binascii
import json
import os
import re
import sys
import uuid
from datetime import datetime
from pathlib import Path
from typing import Callable
from urllib.parse import unquote, urlparse

try:
    from PySide6.QtCore import QThread, QTimer, Qt, Signal
    from PySide6.QtGui import QKeySequence, QShortcut
    from PySide6.QtWidgets import (
        QApplication,
        QFileDialog,
        QHBoxLayout,
        QMainWindow,
        QMessageBox,
        QVBoxLayout,
        QWidget,
    )
except ImportError as exc:  # pragma: no cover - exercised in dependency-free installs
    raise SystemExit(
        "Titan's native workbench requires PySide6. "
        "Install it with: python -m pip install -e '.[desktop-ui]'"
    ) from exc

from titan_decoder.workbench_ui.models import AnalysisSnapshot
from .debian_services import desktop_services
from .icons import icon
from .sample_archive import SampleArchive
from .theme import STYLESHEET
from .widgets import (
    DecoderDetails,
    DecoderWorkbench,
    InvestigationPanel,
    NavigationColumn,
    RecentSamplesDialog,
    ResultsPanel,
    StatusCards,
    TitanMultilineDialog,
    TitanTextDialog,
    WorkbenchFooter,
    WorkbenchHeader,
)


def _apply_dark_windows_frame(widget: QWidget) -> None:
    """Apply Titan caption colors to ordinary Windows-owned dialog frames."""
    if sys.platform != "win32":
        return
    try:
        import ctypes

        handle = ctypes.c_void_p(int(widget.winId()))
        dwm = ctypes.windll.dwmapi

        enabled = ctypes.c_int(1)
        for attribute in (20, 19):  # DWMWA_USE_IMMERSIVE_DARK_MODE
            if (
                dwm.DwmSetWindowAttribute(
                    handle,
                    attribute,
                    ctypes.byref(enabled),
                    ctypes.sizeof(enabled),
                )
                == 0
            ):
                break

        # COLORREF values are stored as 0x00BBGGRR.
        for attribute, colorref in (
            (34, 0x00654D2B),  # DWMWA_BORDER_COLOR    #2b4d65
            (35, 0x00221509),  # DWMWA_CAPTION_COLOR   #091522
            (36, 0x00ECE4DC),  # DWMWA_TEXT_COLOR      #dce4ec
        ):
            value = ctypes.c_uint(colorref)
            dwm.DwmSetWindowAttribute(
                handle,
                attribute,
                ctypes.byref(value),
                ctypes.sizeof(value),
            )
    except (AttributeError, OSError, ValueError):
        # Older Windows builds simply keep their normal system frame.
        return


def _prepare_dark_windows_frame(widget: QWidget) -> None:
    """Set the frame now and once more after Qt shows the native window."""
    _apply_dark_windows_frame(widget)
    QTimer.singleShot(0, lambda: _apply_dark_windows_frame(widget))


class AnalysisThread(QThread):
    completed = Signal(object)
    failed = Signal(str)
    progress = Signal(object)

    def __init__(self, operation: Callable[[], object]):
        super().__init__()
        self.operation = operation

    def run(self) -> None:
        try:
            self.completed.emit(self.operation())
        except Exception as exc:  # pragma: no cover - depends on analyst input
            self.failed.emit(str(exc))


class TitanDesktopWindow(QMainWindow):
    """Frameless desktop shell matching the approved Titan reference."""

    TITLE = "Titan Forensic Workbench"
    REFERENCE_SIZE = (1536, 1024)
    NETWORK_WARNING = (
        "WARNING: Enable online analysis?\n\n"
        "Network-capable analyzers and plugins will be allowed to contact external "
        "services. They may transmit URLs, domains, hashes, indicators, or other "
        "sample-derived data.\n\n"
        "Titan does not automatically upload the evidence file, but third-party "
        "plugins control their own network requests. Only enable this mode when "
        "the evidence and investigation policy permit external communication."
    )

    def __init__(self):
        super().__init__()
        self.services = desktop_services()
        self.snapshot = AnalysisSnapshot()
        self.archive = SampleArchive()
        self.current_sample_id: str | None = None
        self.analysis_sample_id: str | None = None
        self.recent_dialog: RecentSamplesDialog | None = None
        self.tool_dialog: TitanTextDialog | None = None
        self.selected_decoder = 0
        self.current_data = b""
        self.worker: AnalysisThread | None = None
        self.session_id = uuid.uuid4().hex[:8]
        self.started_at = datetime.now().strftime("%H:%M:%S")
        if os.name == "nt":
            self._migrate_existing_reports()

        self.setWindowTitle(self.TITLE)
        self.setWindowIcon(icon("shield", "#25b7ff"))
        self.setWindowFlag(Qt.WindowType.FramelessWindowHint, True)
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setMinimumSize(1180, 760)
        self.resize(*self.REFERENCE_SIZE)
        self.setStyleSheet(STYLESHEET)
        self._build_ui()
        self._wire_shortcuts()

    def _build_ui(self) -> None:
        root = QWidget()
        root.setObjectName("root")
        root_layout = QVBoxLayout(root)
        root_layout.setContentsMargins(1, 1, 1, 1)
        root_layout.setSpacing(0)

        self.header = WorkbenchHeader(
            self.services.state,
            self.services.engine_version(),
            self.session_id,
        )
        self.header.minimize_button.clicked.connect(self.showMinimized)
        self.header.maximize_button.clicked.connect(self._toggle_maximized)
        self.header.close_button.clicked.connect(self.close)
        self.header.profile_requested.connect(self._cycle_profile)
        self.header.network_requested.connect(self._toggle_network)
        self.header.aggressive_requested.connect(self._toggle_aggressive)
        root_layout.addWidget(self.header)

        body = QWidget()
        body_layout = QHBoxLayout(body)
        body_layout.setContentsMargins(14, 14, 16, 14)
        body_layout.setSpacing(14)

        self.navigation = NavigationColumn()
        self.navigation.route_selected.connect(self._route_selected)
        body_layout.addWidget(self.navigation)

        center = QWidget()
        center_layout = QVBoxLayout(center)
        center_layout.setContentsMargins(0, 0, 0, 0)
        center_layout.setSpacing(0)
        self.investigation = InvestigationPanel()
        self.investigation.path_requested.connect(self._choose_path)
        self.investigation.path_dropped.connect(self._analyze_path)
        self.investigation.paste_requested.connect(self._paste_input)
        self.investigation.hex_requested.connect(self._hex_input)
        self.investigation.recent_requested.connect(self._show_recent_samples)
        center_layout.addWidget(self.investigation)
        center_layout.addSpacing(14)

        plugin_count, _plugin_errors = self.services.plugin_status()
        self.status_cards = StatusCards(
            self.services.state,
            engine_version=self.services.engine_version(),
            session_id=self.session_id,
            started_at=self.started_at,
            decoder_count=self.services.decoder_count(),
            plugin_count=plugin_count,
            metrics=self.services.system_metrics(),
            snapshot=self.snapshot,
        )
        center_layout.addWidget(self.status_cards)
        center_layout.addSpacing(18)
        self.results = ResultsPanel(self.snapshot, self.services.state)
        self.results.sample_selected.connect(self._open_archived_sample)
        self.results.sample_save_requested.connect(self._save_archived_sample)
        self.results.sample_remove_requested.connect(self._remove_from_latest)
        self._refresh_sample_history()
        center_layout.addWidget(self.results, 1)
        body_layout.addWidget(center, 1)

        right = QWidget()
        right.setFixedWidth(396)
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(0)
        rows = self.services.decoder_rows()
        self.decoders = DecoderWorkbench(rows)
        self.decoders.setFixedHeight(496)
        self.decoders.decoder_selected.connect(self._select_decoder)
        right_layout.addWidget(self.decoders)
        right_layout.addSpacing(14)
        label, description = self.services.decoder_details(self.selected_decoder)
        self.decoder_details = DecoderDetails(label, description, self.snapshot)
        self.decoder_details.copy_requested.connect(self._copy_output)
        self.decoder_details.save_requested.connect(self._save_output)
        self.decoder_details.run_requested.connect(self._run_decoder)
        right_layout.addWidget(self.decoder_details, 1)
        body_layout.addWidget(right)
        root_layout.addWidget(body, 1)

        footer_wrap = QWidget()
        footer_wrap.setObjectName("footerWrap")
        footer_layout = QHBoxLayout(footer_wrap)
        footer_layout.setContentsMargins(14, 0, 16, 8)
        footer_layout.setSpacing(0)
        self.footer = WorkbenchFooter(self.services.state)
        footer_layout.addWidget(self.footer)
        root_layout.addWidget(footer_wrap)
        self.setCentralWidget(root)

    def _wire_shortcuts(self) -> None:
        self.keyboard_shortcuts: dict[str, QShortcut] = {}
        route_shortcuts = (
            ("H", "dashboard"),
            ("A", "investigation"),
            ("D", "decoders"),
            ("R", "reports"),
            ("P", "plugins"),
            ("S", "settings"),
            ("?", "help"),
            ("Ctrl+L", "refresh"),
            ("Q", "quit"),
        )
        for key, route in route_shortcuts:
            shortcut = QShortcut(QKeySequence(key), self)
            shortcut.activated.connect(lambda value=route: self._route_selected(value))
            self.keyboard_shortcuts[key] = shortcut
        paste_shortcut = QShortcut(QKeySequence("Ctrl+V"), self)
        paste_shortcut.activated.connect(self._paste_clipboard_evidence)
        self.keyboard_shortcuts["Ctrl+V"] = paste_shortcut
        escape_shortcut = QShortcut(QKeySequence("Escape"), self)
        escape_shortcut.activated.connect(self._escape_action)
        self.keyboard_shortcuts["Escape"] = escape_shortcut

    def _toggle_maximized(self) -> None:
        if self.isMaximized():
            self.showNormal()
        else:
            self.showMaximized()

    def _escape_action(self) -> None:
        if self.worker is not None and self.worker.isRunning():
            self.worker.requestInterruption()
            self.services.cancel_current()
            self.footer.set_activity("Cancelling analysis…")
            return
        self.close()

    def _engine_controls_available(self) -> bool:
        if self.worker is not None and self.worker.isRunning():
            self.footer.set_activity("Wait for the current analysis to finish")
            return False
        return True

    def _apply_engine_state(self, activity: str, **changes: object) -> None:
        state = self.services.update_state(**changes)
        self.header.refresh_state(state)
        self.status_cards.refresh_state(state)
        self.results.refresh(self.snapshot, state)
        self.footer.refresh_state(state)
        self.footer.set_activity(activity)

    def _cycle_profile(self) -> None:
        if not self._engine_controls_available():
            return
        profiles = ("fast", "full", "safe")
        current = self.services.state.profile
        try:
            profile = profiles[(profiles.index(current) + 1) % len(profiles)]
        except ValueError:
            profile = profiles[0]
        self._apply_engine_state(
            f"Analysis profile changed to {profile.upper()}",
            profile=profile,
        )

    def _toggle_network(self) -> None:
        if not self._engine_controls_available():
            return
        state = self.services.state
        if state.offline and not self._confirm_network_enable():
            return
        offline = not state.offline
        self._apply_engine_state(
            "Network access disabled" if offline else "Network access enabled",
            offline=offline,
        )

    def _toggle_aggressive(self) -> None:
        if not self._engine_controls_available():
            return
        aggressive = not self.services.state.aggressive
        self._apply_engine_state(
            "Aggressive decoding enabled"
            if aggressive
            else "Aggressive decoding disabled",
            aggressive=aggressive,
        )

    def _confirm_network_enable(self) -> bool:
        dialog = QMessageBox(self)
        dialog.setWindowTitle("Enable Network Access")
        dialog.setIcon(QMessageBox.Icon.Warning)
        dialog.setText(self.NETWORK_WARNING)
        dialog.setStandardButtons(
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel
        )
        dialog.setDefaultButton(QMessageBox.StandardButton.Cancel)
        enable_button = dialog.button(QMessageBox.StandardButton.Yes)
        if enable_button is not None:
            enable_button.setText("Enable Online Mode")
        _prepare_dark_windows_frame(dialog)
        return dialog.exec() == QMessageBox.StandardButton.Yes

    def _route_selected(self, route: str) -> None:
        nav_button = self.navigation.nav_buttons.get(route)
        if nav_button is not None:
            nav_button.setChecked(True)
        routes: dict[str, Callable[[], None]] = {
            "dashboard": self._show_dashboard,
            "investigation": self._paste_input,
            "decoders": self._show_decoder_workbench,
            "reports": self._show_recent_samples,
            "memory": self._show_memory_analysis,
            "file-analysis": self._show_file_analysis,
            "correlation": self._show_correlation,
            "plugins": self._show_plugins,
            "iocs": self._show_ioc_manager,
            "settings": self._show_settings,
            "help": self._show_help,
            "refresh": self._refresh_workspace,
            "quit": self._quit,
        }
        callback = routes.get(route)
        if callback is None:
            self._show_error(f"Unknown workspace route: {route}")
            return
        callback()

    def _quit(self) -> None:
        self.close()

    def _show_dashboard(self) -> None:
        self.results.tabs.setCurrentIndex(0)
        self.footer.set_activity("Dashboard ready")

    def _show_decoder_workbench(self) -> None:
        self.decoders.search.setFocus()
        self.decoders.search.selectAll()
        self.footer.set_activity("Decoder Workbench ready")

    def _choose_path(
        self,
        title: str = "Select evidence",
        name_filter: str = "All files (*)",
    ) -> None:
        dialog = QFileDialog(
            self,
            title,
            str(self._default_evidence_directory()),
        )
        dialog.setOption(QFileDialog.Option.DontUseNativeDialog, True)
        dialog.setFileMode(QFileDialog.FileMode.ExistingFile)
        dialog.setNameFilter(name_filter)
        dialog.setViewMode(QFileDialog.ViewMode.Detail)
        dialog.resize(900, 600)
        _prepare_dark_windows_frame(dialog)
        if dialog.exec() and dialog.selectedFiles():
            self._analyze_path(dialog.selectedFiles()[0])

    def _show_memory_analysis(self) -> None:
        self._choose_path(
            "Select memory image",
            "Memory images (*.raw *.mem *.dmp *.dump *.vmem);;All files (*)",
        )

    def _show_file_analysis(self) -> None:
        dialog = QMessageBox(self)
        dialog.setWindowTitle("File Analysis")
        dialog.setIcon(QMessageBox.Icon.Information)
        dialog.setText("Choose an individual analysis or a recursive static scan.")
        dialog.setInformativeText(
            "Deep Scan walks a folder without executing its files and can copy "
            "confirmed malicious results into recoverable quarantine."
        )
        file_button = dialog.addButton(
            "Analyze File", QMessageBox.ButtonRole.ActionRole
        )
        folder_button = dialog.addButton(
            "Deep Scan Folder", QMessageBox.ButtonRole.ActionRole
        )
        dialog.addButton(QMessageBox.StandardButton.Cancel)
        dialog.setDefaultButton(file_button)
        _prepare_dark_windows_frame(dialog)
        dialog.exec()
        if dialog.clickedButton() is file_button:
            self._choose_path("Select file for analysis", "All files (*)")
        elif dialog.clickedButton() is folder_button:
            self._choose_deep_scan_folder()

    def _choose_deep_scan_folder(self) -> None:
        dialog = QFileDialog(
            self,
            "Select folder for deep scan",
            str(self._default_evidence_directory()),
        )
        dialog.setOption(QFileDialog.Option.DontUseNativeDialog, True)
        dialog.setOption(QFileDialog.Option.ShowDirsOnly, True)
        dialog.setFileMode(QFileDialog.FileMode.Directory)
        dialog.resize(900, 600)
        _prepare_dark_windows_frame(dialog)
        if not dialog.exec() or not dialog.selectedFiles():
            return
        path = self._normalize_external_path(dialog.selectedFiles()[0])
        choice = QMessageBox(self)
        choice.setWindowTitle("Deep Scan Safety")
        choice.setIcon(QMessageBox.Icon.Warning)
        choice.setText("Deep Scan never executes samples.")
        choice.setInformativeText(
            "Scan Only leaves every source file untouched. Scan + Quarantine "
            "copies only MALICIOUS verdicts into Titan's recoverable vault; it "
            "does not delete or move the originals."
        )
        scan_only = choice.addButton("Scan Only", QMessageBox.ButtonRole.AcceptRole)
        quarantine = choice.addButton(
            "Scan + Quarantine", QMessageBox.ButtonRole.ActionRole
        )
        choice.addButton(QMessageBox.StandardButton.Cancel)
        choice.setDefaultButton(scan_only)
        _prepare_dark_windows_frame(choice)
        choice.exec()
        if choice.clickedButton() not in {scan_only, quarantine}:
            return
        self._start_deep_scan(
            path,
            quarantine_malicious=choice.clickedButton() is quarantine,
        )

    def _start_deep_scan(
        self,
        path: Path,
        *,
        quarantine_malicious: bool,
    ) -> None:
        if self.worker is not None and self.worker.isRunning():
            return
        self.footer.set_activity("Starting deep scan… (Esc to cancel)")
        self.worker = AnalysisThread(
            lambda: self.services.deep_scan_path(
                path,
                quarantine_malicious=quarantine_malicious,
            )
        )
        self.services.set_progress_callback(self.worker.progress.emit)
        self.worker.progress.connect(self._analysis_progress)
        self.worker.completed.connect(self._deep_scan_finished)
        self.worker.failed.connect(self._analysis_failed)
        self.worker.finished.connect(self._worker_finished)
        self.worker.start()

    def _deep_scan_finished(self, summary: object) -> None:
        if not isinstance(summary, dict):
            self._analysis_failed("The deep-scan backend returned an invalid result.")
            return
        analyzed = int(summary.get("analyzed_count") or 0)
        errors = int(summary.get("error_count") or 0)
        quarantined = sum(
            bool(item.get("quarantine"))
            for item in summary.get("results") or []
            if isinstance(item, dict)
        )
        self.footer.set_activity(None)
        self._show_tool_dialog(
            "Deep Scan Results",
            f"{analyzed} analyzed · {errors} errors · {quarantined} quarantined",
            json.dumps(summary, indent=2, ensure_ascii=False),
        )

    def _show_tool_dialog(self, title: str, summary: str, content: str) -> None:
        dialog = TitanTextDialog(self, title, summary, content)
        self.tool_dialog = dialog
        dialog.exec()
        self.tool_dialog = None

    def _show_correlation(self) -> None:
        relationships = self.snapshot.relationships
        if relationships:
            content = json.dumps(relationships, indent=2, ensure_ascii=False)
            summary = (
                f"{len(relationships)} relationship(s) from "
                f"{self.snapshot.source_name}."
            )
        else:
            content = (
                "No relationships are available for the current sample.\n\n"
                "Analyze or reopen evidence containing related indicators, "
                "artifacts, or timeline events, then return here."
            )
            summary = "Correlation is ready, but the current result has no links."
        self._show_tool_dialog("Correlation Engine", summary, content)

    def _show_plugins(self) -> None:
        plugin_count, error_count = self.services.plugin_status()
        configured = self.services.config.get("plugin_dirs", []) or []
        directories = [str(Path.home() / ".titan_decoder" / "plugins")]
        directories.extend(str(value) for value in configured)
        content = "\n".join(
            (
                f"Loaded plugins: {plugin_count}",
                f"Load errors: {error_count}",
                "",
                "Search directories:",
                *(f"  - {value}" for value in directories),
                "",
                "Plugins are loaded locally when the workbench starts.",
            )
        )
        self._show_tool_dialog(
            "Plugins",
            "Installed Titan analysis extensions and their load status.",
            content,
        )

    def _show_ioc_manager(self) -> None:
        if self.snapshot.iocs:
            content = json.dumps(self.snapshot.iocs, indent=2, ensure_ascii=False)
            summary = (
                f"{self.snapshot.ioc_count} indicator(s) extracted from "
                f"{self.snapshot.source_name}."
            )
        else:
            content = (
                "No indicators are loaded.\n\n"
                "Open or analyze a sample to collect URLs, IP addresses, "
                "email addresses, domains, and file hashes."
            )
            summary = "IOC Manager is ready; the current result contains no indicators."
        self._show_tool_dialog("IOC Manager", summary, content)

    def _show_settings(self) -> None:
        state = self.services.state
        content = "\n".join(
            (
                f"Analysis profile: {state.profile.upper()}",
                f"Network access: {'OFFLINE' if state.offline else 'ONLINE'}",
                f"Aggressive decoding: {'ON' if state.aggressive else 'OFF'}",
                f"Debian backend: {getattr(self.services, 'distribution', 'local')}",
                f"Reports directory: {state.reports_dir}",
                f"Sample archive: {self.archive.root}",
                "",
                "Titan keeps evidence and reports local unless network access is enabled.",
            )
        )
        self._show_tool_dialog(
            "Settings",
            "Current workbench and analysis-engine configuration.",
            content,
        )

    def _show_help(self) -> None:
        content = """GETTING STARTED
  Drop a file into Investigation Workspace, click the drop zone, or press A.
  Select a decoder on the right and choose Run Decoder for a manual decode.
  Use Recent Samples to reopen, save, or permanently delete archived evidence.

KEYBOARD SHORTCUTS
  H       Dashboard
  A       Analyze Input
  D       Decoder Workbench
  R       Reports Browser
  P       Plugins
  S       Settings
  ?       Help & Docs
  Ctrl+L  Refresh workspace
  Q       Quit

NAVIGATION
  Memory Analysis loads a memory image for static inspection.
  File Analysis loads one file or starts a recursive static Deep Scan.
  Deep Scan can copy MALICIOUS verdicts into recoverable quarantine.
  Correlation Engine displays relationships from the current report.
  IOC Manager displays indicators extracted from the current report.
"""
        self._show_tool_dialog(
            "Help & Docs",
            "Titan Forensic Workbench controls and analysis workflow.",
            content,
        )

    def _refresh_workspace(self) -> None:
        if os.name == "nt":
            self._migrate_existing_reports()
        self._refresh_sample_history()
        self.status_cards.refresh_state(self.services.state)
        self.status_cards.refresh_snapshot(self.snapshot)
        self.status_cards.resources.set_resource_rows(self.services.system_metrics())
        self.results.refresh(self.snapshot, self.services.state)
        self.decoder_details.refresh_snapshot(self.snapshot)
        if self.recent_dialog is not None:
            self.recent_dialog.set_records(self.archive.records(include_hidden=True))
        self.footer.set_activity("Workspace refreshed")

    @staticmethod
    def _default_evidence_directory() -> Path:
        cwd = Path.cwd()
        for candidate in (cwd, *cwd.parents):
            if candidate.parent.name.lower() == "users":
                desktop = candidate / "Desktop"
                if desktop.is_dir():
                    return desktop
        return Path.home()

    @staticmethod
    def _normalize_external_path(value: str | Path) -> Path:
        raw = str(value).strip().strip("\"'")
        if raw.lower().startswith("file://"):
            parsed = urlparse(raw)
            raw = unquote(parsed.path)
            if parsed.netloc:
                raw = f"//{parsed.netloc}{raw}"
            elif os.name == "nt" and re.match(r"^/[A-Za-z]:/", raw):
                # Qt/URI file drops use /C:/... while pathlib on Windows needs
                # C:/... .  Linux keeps the leading slash until the WSL
                # mapping below is applied.
                raw = raw[1:]
        windows_path = re.match(
            r"^/?(?P<drive>[A-Za-z]):[\\/](?P<tail>.*)$",
            raw,
            re.DOTALL,
        )
        if windows_path and os.name != "nt":
            drive = windows_path.group("drive").lower()
            tail = windows_path.group("tail").replace("\\", "/")
            return Path(f"/mnt/{drive}/{tail}")
        return Path(raw).expanduser()

    def _paste_clipboard_evidence(self) -> None:
        clipboard = QApplication.clipboard()
        mime = clipboard.mimeData()
        candidates = [url.toLocalFile() or url.toString() for url in mime.urls()]
        if mime.hasText():
            candidates.extend(mime.text().splitlines())
        for candidate in candidates:
            path = self._normalize_external_path(candidate)
            if path.exists():
                self._analyze_path(path)
                return
        text = clipboard.text().strip()
        if text:
            data = text.encode("utf-8")
            self.current_data = data
            sample_id = self._archive_evidence(data, "clipboard-input.txt")
            self._start_analysis(
                lambda: self.services.analyze(data, "clipboard input"),
                sample_id=sample_id,
            )

    def _paste_input(self) -> None:
        text, accepted = TitanMultilineDialog.get_text(
            self,
            "Analyze Input",
            "Paste text or encoded data:",
            action_text="Analyze",
        )
        if accepted and text:
            data = text.encode("utf-8")
            self.current_data = data
            sample_id = self._archive_evidence(data, "pasted-input.txt")
            self._start_analysis(
                lambda: self.services.analyze(data, "pasted input"),
                sample_id=sample_id,
            )

    def _hex_input(self) -> None:
        text, accepted = TitanMultilineDialog.get_text(
            self,
            "Analyze Hex",
            "Enter a hexadecimal byte string:",
            action_text="Decode",
        )
        if not accepted or not text:
            return
        try:
            data = binascii.unhexlify("".join(text.split()))
        except (binascii.Error, ValueError) as exc:
            self._show_error(f"Invalid hexadecimal input: {exc}")
            return
        self.current_data = data
        sample_id = self._archive_evidence(data, "hex-input.bin")
        self._start_analysis(
            lambda: self.services.analyze(data, "hex input"),
            sample_id=sample_id,
        )

    def _analyze_path(self, value: str | Path) -> None:
        path = self._normalize_external_path(value)
        if not path.exists():
            self._show_error(f"Evidence path was not found: {path}")
            return
        if path.is_file():
            try:
                self.current_data = self.services.read_file(path)
            except Exception as exc:
                self._show_error(str(exc))
                return
            sample_id = self._archive_evidence(
                self.current_data,
                path.name,
                source_path=str(path),
            )
        else:
            self.current_data = b""
            sample_id = None
        self._start_analysis(
            lambda: self.services.analyze_path(path),
            sample_id=sample_id,
        )

    def _migrate_existing_reports(self) -> None:
        """Seed the archive with reports created before sample history existed."""
        for report_path in self.services.reports()[:100]:
            try:
                snapshot = self.services.load_report(report_path)
                self.archive.import_snapshot(
                    snapshot,
                    source_path=str(report_path.resolve()),
                )
            except Exception:
                continue

    def _refresh_sample_history(self) -> None:
        if not hasattr(self, "results"):
            return
        self.results.refresh_history(
            self.archive.records(include_hidden=False),
            self.current_sample_id,
        )

    def _open_archived_sample(self, sample_id: str) -> None:
        record = self.archive.get(sample_id)
        if record is None:
            self._show_error("The selected archived sample no longer exists.")
            self._refresh_sample_history()
            return
        try:
            self.archive.set_latest_visibility(sample_id, True)
            data = self.archive.load_evidence(sample_id)
            snapshot = self.archive.load_snapshot(sample_id)
        except Exception as exc:
            self._show_error(str(exc))
            return
        self.current_data = data or b""
        self.current_sample_id = sample_id
        if snapshot is not None:
            self._apply_snapshot(snapshot, sample_id=sample_id)
            self.footer.set_activity(f"Opened {record.name}")
        elif data is not None:
            self._start_analysis(
                lambda: self.services.analyze(data, record.name),
                sample_id=sample_id,
            )
        else:
            self._show_error("This archived entry has no evidence or saved analysis.")

    def _remove_from_latest(self, sample_id: str) -> None:
        self.archive.set_latest_visibility(sample_id, False)
        if self.current_sample_id == sample_id:
            self._clear_current_analysis()
        else:
            self._refresh_sample_history()
        self.footer.set_activity("Removed from Latest; retained in Recent Samples")

    def _clear_current_analysis(self) -> None:
        self.current_sample_id = None
        self.current_data = b""
        self._apply_snapshot(AnalysisSnapshot())

    def _show_recent_samples(self) -> None:
        dialog = RecentSamplesDialog(self, self.archive.records(include_hidden=True))
        self.recent_dialog = dialog
        dialog.open_requested.connect(self._open_from_recent_dialog)
        dialog.save_requested.connect(self._save_archived_sample)
        dialog.delete_requested.connect(self._delete_archived_sample)
        dialog.exec()
        self.recent_dialog = None

    def _open_from_recent_dialog(self, sample_id: str) -> None:
        if self.recent_dialog is not None:
            self.recent_dialog.accept()
        self._open_archived_sample(sample_id)

    def _save_archived_sample(self, sample_id: str) -> None:
        record = self.archive.get(sample_id)
        if record is None:
            self._show_error("The selected archived sample no longer exists.")
            return
        default_name = record.name
        if record.evidence_file is None and not default_name.lower().endswith(".json"):
            default_name = f"{Path(default_name).stem}-analysis.json"
        parent = self.recent_dialog or self
        dialog = QFileDialog(
            parent,
            "Save archived sample",
            str(self._default_evidence_directory() / default_name),
        )
        dialog.setOption(QFileDialog.Option.DontUseNativeDialog, True)
        dialog.setAcceptMode(QFileDialog.AcceptMode.AcceptSave)
        dialog.setFileMode(QFileDialog.FileMode.AnyFile)
        dialog.setNameFilter("All files (*)")
        dialog.setViewMode(QFileDialog.ViewMode.Detail)
        dialog.resize(900, 600)
        _prepare_dark_windows_frame(dialog)
        if not dialog.exec() or not dialog.selectedFiles():
            return
        try:
            destination = self.archive.save_copy(
                sample_id,
                Path(dialog.selectedFiles()[0]),
            )
        except Exception as exc:
            self._show_error(str(exc))
            return
        self.footer.set_activity(f"Saved {destination.name}")

    def _delete_archived_sample(self, sample_id: str) -> None:
        record = self.archive.get(sample_id)
        if record is None:
            return
        if not self._confirm_permanent_delete(record.name):
            return
        try:
            self.archive.delete_permanently(sample_id)
        except Exception as exc:
            self._show_error(str(exc))
            return
        if self.current_sample_id == sample_id:
            self._clear_current_analysis()
        else:
            self._refresh_sample_history()
        if self.recent_dialog is not None:
            self.recent_dialog.set_records(self.archive.records(include_hidden=True))
        self.footer.set_activity(f"Permanently deleted {record.name}")

    def _confirm_permanent_delete(self, name: str) -> bool:
        parent = self.recent_dialog or self
        dialog = QMessageBox(parent)
        dialog.setWindowTitle("Delete Archived Sample")
        dialog.setIcon(QMessageBox.Icon.Warning)
        dialog.setText(
            f"Permanently delete {name}?\n\n"
            "Its saved evidence and analysis will be removed from Recent Samples."
        )
        dialog.setStandardButtons(
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel
        )
        dialog.setDefaultButton(QMessageBox.StandardButton.Cancel)
        _prepare_dark_windows_frame(dialog)
        return dialog.exec() == QMessageBox.StandardButton.Yes

    def _archive_evidence(
        self,
        data: bytes,
        name: str,
        *,
        source_path: str | None = None,
    ) -> str | None:
        try:
            record = self.archive.archive_bytes(
                data,
                name,
                source_path=source_path,
            )
        except Exception as exc:
            self._show_error(
                f"The evidence could not be added to Recent Samples: {exc}"
            )
            return None
        self.current_sample_id = record.id
        self._refresh_sample_history()
        return record.id

    def _start_analysis(
        self,
        operation: Callable[[], AnalysisSnapshot],
        *,
        sample_id: str | None = None,
    ) -> None:
        if self.worker is not None and self.worker.isRunning():
            return
        self.analysis_sample_id = sample_id
        self.footer.set_activity("Analyzing evidence… (Esc to cancel)")
        self.worker = AnalysisThread(operation)
        self.services.set_progress_callback(self.worker.progress.emit)
        self.worker.progress.connect(self._analysis_progress)
        self.worker.completed.connect(self._analysis_finished)
        self.worker.failed.connect(self._analysis_failed)
        self.worker.finished.connect(self._worker_finished)
        self.worker.start()

    def _analysis_progress(self, event: object) -> None:
        if not isinstance(event, dict):
            return
        message = str(event.get("message") or "Analyzing evidence")
        percent = event.get("percent")
        if isinstance(percent, int):
            message = f"{message} ({percent}%)"
        self.footer.set_activity(f"{message} · Esc to cancel")

    def _analysis_finished(self, snapshot: AnalysisSnapshot) -> None:
        sample_id = self.analysis_sample_id
        try:
            if sample_id is None:
                archived = self.archive.import_snapshot(snapshot)
                sample_id = archived.id if archived is not None else None
            else:
                self.archive.attach_snapshot(sample_id, snapshot)
        except Exception as exc:
            self._show_error(
                f"The analysis completed but history could not be saved: {exc}"
            )
        self._apply_snapshot(snapshot, sample_id=sample_id)
        self.footer.set_activity(None)

    def _analysis_failed(self, message: str) -> None:
        if "cancelled" in message.lower():
            self.footer.set_activity("Analysis cancelled")
        else:
            self.footer.set_activity(None)
            self._show_error(message)

    def _worker_finished(self) -> None:
        self.services.set_progress_callback(None)
        if self.worker is not None:
            self.worker.deleteLater()
            self.worker = None
        self.analysis_sample_id = None

    def _apply_snapshot(
        self,
        snapshot: AnalysisSnapshot,
        *,
        sample_id: str | None = None,
    ) -> None:
        self.snapshot = snapshot
        if sample_id is not None:
            self.current_sample_id = sample_id
        self.status_cards.refresh_snapshot(snapshot)
        self.results.refresh(snapshot, self.services.state)
        self.decoder_details.refresh_snapshot(snapshot)
        self._refresh_sample_history()

    def _select_decoder(self, index: int) -> None:
        self.selected_decoder = index
        label, description = self.services.decoder_details(index)
        self.decoder_details.refresh_decoder(label, description)

    def _run_decoder(self) -> None:
        if not self.current_data:
            self._show_error("Load or paste evidence before running a decoder.")
            return
        if self.worker is not None and self.worker.isRunning():
            return
        self.footer.set_activity("Running decoder… (Esc to cancel)")
        self.worker = AnalysisThread(
            lambda: self.services.run_decoder(
                self.selected_decoder,
                self.current_data,
                self.snapshot.source_name,
            )
        )
        self.services.set_progress_callback(self.worker.progress.emit)
        self.worker.progress.connect(self._analysis_progress)
        self.worker.completed.connect(self._decoder_finished)
        self.worker.failed.connect(self._analysis_failed)
        self.worker.finished.connect(self._worker_finished)
        self.worker.start()

    def _decoder_finished(self, snapshot: AnalysisSnapshot) -> None:
        self.snapshot.decoded_output = snapshot.decoded_output
        self.snapshot.input_preview = snapshot.input_preview
        self.snapshot.decoder_label = snapshot.decoder_label
        self.snapshot.decoder_success = snapshot.decoder_success
        self.decoder_details.refresh_snapshot(self.snapshot)
        self.footer.set_activity(None)

    def _copy_output(self) -> None:
        if self.snapshot.decoded_output is None:
            self._show_error("There is no decoder output to copy.")
            return
        QApplication.clipboard().setText(
            self.snapshot.decoded_output.decode("utf-8", errors="replace")
        )
        self.footer.set_activity("Output copied")

    def _save_output(self) -> None:
        if self.snapshot.decoded_output is None:
            self._show_error("There is no decoder output to save.")
            return
        dialog = QFileDialog(
            self,
            "Save decoder output",
            str(Path.home() / "decoded-output.bin"),
        )
        dialog.setOption(QFileDialog.Option.DontUseNativeDialog, True)
        dialog.setAcceptMode(QFileDialog.AcceptMode.AcceptSave)
        dialog.setFileMode(QFileDialog.FileMode.AnyFile)
        dialog.setNameFilter("All files (*)")
        dialog.setViewMode(QFileDialog.ViewMode.Detail)
        dialog.resize(900, 600)
        _prepare_dark_windows_frame(dialog)
        if dialog.exec() and dialog.selectedFiles():
            destination = dialog.selectedFiles()[0]
            Path(destination).write_bytes(self.snapshot.decoded_output)
            self.footer.set_activity("Output saved")

    def _show_error(self, message: str) -> None:
        self._show_message(QMessageBox.Icon.Warning, message)

    def _show_message(self, icon_type: QMessageBox.Icon, message: str) -> None:
        dialog = QMessageBox(self)
        dialog.setWindowTitle(self.TITLE)
        dialog.setIcon(icon_type)
        dialog.setText(message)
        dialog.setStandardButtons(QMessageBox.StandardButton.Ok)
        _prepare_dark_windows_frame(dialog)
        dialog.exec()


def main() -> None:
    existing = QApplication.instance()
    app = existing if isinstance(existing, QApplication) else QApplication(sys.argv)
    app.setApplicationName(TitanDesktopWindow.TITLE)
    app.setWindowIcon(icon("shield", "#25b7ff"))
    window = TitanDesktopWindow()
    window.show()
    raise SystemExit(app.exec())


if __name__ == "__main__":  # pragma: no cover
    main()
