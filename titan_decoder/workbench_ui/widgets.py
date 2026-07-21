from __future__ import annotations

from datetime import datetime
from pathlib import Path

from textual.app import ComposeResult
from textual.containers import Horizontal, HorizontalScroll, Vertical, VerticalScroll
from textual.events import Paste
from textual.widgets import (
    Button,
    Input,
    Label,
    OptionList,
    Select,
    Static,
    Switch,
    TabbedContent,
    TabPane,
)
from textual.widgets.option_list import Option

from . import icons
from .models import AnalysisSnapshot, WorkbenchState
from .presenters import (
    decoded_text,
    detections_text,
    hex_preview,
    iocs_text,
    markup_escape,
    strings_text,
)


class EvidenceInput(Input):
    """Input that turns a terminal file drop into immediate analysis."""

    def _on_paste(self, event: Paste) -> None:
        accept_drop = getattr(self.app, "accept_dropped_path", None)
        if callable(accept_drop) and accept_drop(event.text):
            event.prevent_default()
            event.stop()
            return
        super()._on_paste(event)


class WorkbenchHeader(Horizontal):
    """Application chrome matching the approved forensic-workbench layout."""

    def __init__(self, state: WorkbenchState, *, version: str, session_id: str):
        super().__init__(id="workbench-header")
        self.state = state
        self.version = version
        self.session_id = session_id

    def compose(self) -> ComposeResult:
        with Horizontal(id="workbench-brand"):
            yield Static(f"[#27b7ff]{icons.SHIELD}[/#27b7ff]", id="brand-shield")
            yield Static(
                "[b]TITAN FORENSIC WORKBENCH[/b] "
                f"[#91a4b7]v{markup_escape(self.version)}[/#91a4b7]",
                id="workbench-title",
            )
        with Horizontal(id="header-status"):
            yield Static(id="profile-chip", classes="status-chip profile-chip")
            yield Static(id="network-chip", classes="status-chip network-chip")
            yield Static(id="aggressive-chip", classes="status-chip aggressive-chip")
        with Horizontal(id="header-right"):
            yield Static(id="session-clock")
            yield Button("─", id="window-minimize", classes="window-control")
            yield Button("□", id="window-maximize", classes="window-control")
            yield Button("×", id="window-close", classes="window-control close-control")

    def on_mount(self) -> None:
        self.refresh_state()
        self._refresh_clock()
        self.set_interval(1.0, self._refresh_clock)

    def refresh_state(self, state: WorkbenchState | None = None) -> None:
        if state is not None:
            self.state = state
        self.query_one("#profile-chip", Static).update(
            f"PROFILE: [b]{markup_escape(self.state.profile.upper())}[/b]"
        )
        self.query_one("#network-chip", Static).update(
            "NETWORK: [b]OFFLINE[/b]"
            if self.state.offline
            else "NETWORK: [b]ONLINE[/b]"
        )
        self.query_one("#aggressive-chip", Static).update(
            f"AGGRESSIVE: [b]{'ON' if self.state.aggressive else 'OFF'}[/b]"
        )

    def _refresh_clock(self) -> None:
        self.query_one("#session-clock", Static).update(
            f"SESSION: {self.session_id}   │   {datetime.now():%H:%M:%S}"
        )


class WorkbenchStatusBar(Horizontal):
    """Bottom status strip from the reference layout."""

    def __init__(self, state: WorkbenchState):
        super().__init__(id="workbench-status-bar")
        self.state = state

    def compose(self) -> ComposeResult:
        yield Static(f"[#42d46b]{icons.DOT}[/#42d46b] Ready", id="footer-state")
        yield Static(
            f"Working Directory: {markup_escape(Path.cwd())}",
            id="footer-working-directory",
        )
        yield Static(id="footer-mode")
        yield Static("No updates available", id="footer-updates")
        yield Static("Press ? for help", id="footer-help")

    def on_mount(self) -> None:
        self.refresh_state()

    def refresh_state(self, state: WorkbenchState | None = None) -> None:
        if state is not None:
            self.state = state
        mode = "Offline Mode" if self.state.offline else "Online Mode"
        self.query_one("#footer-mode", Static).update(mode)


class NavigationPanel(VerticalScroll):
    def __init__(self):
        super().__init__(id="navigation-panel")

    def compose(self) -> ComposeResult:
        with Vertical(id="navigation-card", classes="side-card"):
            yield Label("NAVIGATION", classes="panel-heading")
            yield OptionList(
                Option(f"{icons.HOME:<3} Dashboard", id="dashboard"),
                Option(f"{icons.SEARCH:<3} Analyze Input", id="investigation"),
                Option(f"{icons.CODE:<3} Decoder Workbench", id="decoders"),
                Option(f"{icons.FOLDER:<3} Reports Browser", id="reports"),
                Option(f"{icons.MEMORY:<3} Memory Analysis", id="memory"),
                Option(f"{icons.FILE:<3} File Analysis", id="file-analysis"),
                Option(f"{icons.GRAPH:<3} Correlation Engine", id="correlation"),
                Option(f"{icons.PLUGIN:<3} Plugins", id="plugins"),
                Option(f"{icons.TARGET:<3} IOC Manager", id="iocs"),
                Option(f"{icons.SETTINGS:<3} Settings", id="settings"),
                Option(f"{icons.BOOK:<3} Help & Docs", id="help"),
                id="navigation-list",
            )
        with Vertical(id="shortcuts-card", classes="side-card"):
            yield Label("SHORTCUTS", classes="panel-heading")
            yield Static(
                "[b] H [/b]  Dashboard\n"
                "[b] A [/b]  Analyze Input\n"
                "[b] D [/b]  Decoder Workbench\n"
                "[b] R [/b]  Reports Browser\n"
                "[b] P [/b]  Plugins\n"
                "[b] S [/b]  Settings\n"
                "[b] ? [/b]  Help\n"
                "[b]Ctrl+L[/b] Refresh\n"
                "[b] Q [/b]  Quit",
                classes="shortcut-list",
            )
        yield Static("", id="navigation-spacer")
        yield Static(
            f"[#27b7ff]{icons.SHIELD}  [b]TITAN[/b][/#27b7ff]\n"
            "[#279ce7]DETERMINISTIC ANALYSIS[/#279ce7]\n"
            "[#a4b2c0]POWERED BY TITAN ENGINE[/#a4b2c0]",
            classes="brand-card",
        )


class InvestigationPanel(Vertical):
    def __init__(self):
        super().__init__(id="investigation-panel")

    def compose(self) -> ComposeResult:
        yield Label("INVESTIGATION WORKSPACE", classes="panel-heading")
        with Horizontal(id="input-row"):
            yield EvidenceInput(
                placeholder="Paste text, hex, or a file/folder path…",
                id="evidence-input",
            )
            yield Button("Analyze", id="analyze-button", variant="primary")
        with Horizontal(id="investigation-body"):
            yield Static(
                f"[#a8b9c9]{icons.UPLOAD}[/#a8b9c9]\n\n"
                "[b]DROP FILES HERE[/b]\n"
                "or press [#35d58a][A][/#35d58a] to analyze input",
                id="drop-zone",
            )
            with Vertical(id="quick-start"):
                yield Label("QUICK START", classes="subsection-heading")
                yield OptionList(
                    Option(
                        f"{icons.PASTE}  Paste text / data                 {icons.CHEVRON}",
                        id="paste",
                    ),
                    Option(
                        f"{icons.HEX}  Enter hex string                  {icons.CHEVRON}",
                        id="hex",
                    ),
                    Option(
                        f"{icons.LOAD}  Load from file                    {icons.CHEVRON}",
                        id="file",
                    ),
                    Option(
                        f"{icons.RECENT}  Recent samples                   {icons.CHEVRON}",
                        id="report",
                    ),
                    id="quick-start-list",
                )


class StatusCards(HorizontalScroll):
    def __init__(
        self,
        state: WorkbenchState,
        *,
        engine_version: str,
        decoder_count: int,
        plugin_count: int,
        plugin_errors: int,
        correlation_status: str,
        metrics: dict[str, str],
        session_id: str = "--------",
        started_at: str = "--:--:--",
        snapshot: AnalysisSnapshot | None = None,
    ):
        super().__init__(id="status-cards")
        self.state = state
        self.engine_version = engine_version
        self.decoder_count = decoder_count
        self.plugin_count = plugin_count
        self.plugin_errors = plugin_errors
        self.correlation_status = correlation_status
        self.metrics = metrics
        self.session_id = session_id
        self.started_at = started_at
        self.snapshot = snapshot or AnalysisSnapshot()

    @staticmethod
    def _bar(value: str) -> str:
        try:
            percent = min(max(int(float(value)), 0), 100)
        except (TypeError, ValueError):
            percent = 0
        filled = min(8, round(percent / 12.5))
        active = "━" * filled
        idle = "━" * (8 - filled)
        return (
            f"[#b8b84a]{active}[/#b8b84a]"
            f"[#34414b]{idle}[/#34414b]  {percent:>3}%"
        )

    def _session_text(self) -> str:
        analyzed = 1 if self.snapshot.report else 0
        return (
            "[#d17cff][b]SESSION INFO[/b][/#d17cff]\n\n"
            f"ID          {self.session_id}\n"
            f"Started     {self.started_at}\n"
            f"Artifacts   {self.snapshot.artifact_count}\n"
            f"Analyses    {analyzed}\n"
            f"Decodes     {self.snapshot.decode_count}"
        )

    def _engine_status_text(self) -> str:
        return (
            "[#61e27f][b]ENGINE STATUS[/b][/#61e27f]\n\n"
            f"Engine      v{self.engine_version}\n"
            f"Profile     {self.state.profile.upper()}\n"
            f"Aggressive  {'ON' if self.state.aggressive else 'OFF'}\n"
            f"Network     {'OFFLINE' if self.state.offline else 'ONLINE'}\n"
            "Uptime      active"
        )

    def _resource_text(self) -> str:
        return (
            "[#f1d13e][b]RESOURCE USAGE[/b][/#f1d13e]\n\n"
            f"CPU      {self._bar(self.metrics.get('cpu_percent', '0'))}\n"
            f"Memory   {self._bar(self.metrics.get('memory_percent', '0'))}\n"
            f"Disk I/O {self._bar(self.metrics.get('disk_percent', '0'))}\n"
            f"Workers  {self.metrics.get('workers', '1')}/8"
        )

    def refresh_state(self, state: WorkbenchState) -> None:
        self.state = state
        self.query_one("#engine-status-card", Static).update(self._engine_status_text())

    def refresh_snapshot(self, snapshot: AnalysisSnapshot) -> None:
        self.snapshot = snapshot
        self.query_one("#session-info-card", Static).update(self._session_text())

    def compose(self) -> ComposeResult:
        plugin_value = str(self.plugin_count)
        if self.plugin_errors:
            plugin_value = f"{self.plugin_count}/{self.plugin_errors} err"
        yield Static(
            self._session_text(),
            id="session-info-card",
            classes="metric-card violet-card",
        )
        yield Static(
            "[#56c7ff][b]SYSTEM STATUS[/b][/#56c7ff]\n\n"
            f"Decoders    {self.decoder_count}\n"
            f"Plugins     {plugin_value}\n"
            "Rules       7\n"
            "Signatures  local\n"
            "YARA Rules  optional",
            classes="metric-card blue-card",
        )
        yield Static(
            self._engine_status_text(),
            id="engine-status-card",
            classes="metric-card green-card",
        )
        yield Static(
            self._resource_text(),
            classes="metric-card yellow-card",
        )


class ResultsPanel(Vertical):
    def __init__(
        self,
        snapshot: AnalysisSnapshot,
        state: WorkbenchState | None = None,
    ):
        super().__init__(id="dynamic-view")
        self.snapshot = snapshot
        self.state = state or WorkbenchState()

    def _status_label(self) -> str:
        outcome = self.snapshot.analysis_outcome
        status = str(outcome.get("status") or "waiting")
        labels = {
            "decoded": "Completed",
            "analyzed": "Completed",
            "partial_decode": "Partial Decode",
            "unrecognized": "Unrecognized",
            "limited": "Safety Limited",
            "empty_input": "No Input",
            "waiting": "Waiting",
        }
        return labels.get(status, status.replace("_", " ").title())

    def _overview_text(self) -> str:
        verdict = str(self.snapshot.assurance.get("verdict") or "NOT ASSESSED")
        return (
            "[#73cfff]ANALYSIS OVERVIEW[/#73cfff]\n\n"
            f"Status           [#62df7a]{icons.CHECK} {self._status_label()}[/#62df7a]\n"
            f"Verdict          {markup_escape(verdict.replace('_', ' '))}\n"
            f"Profile          {self.state.profile.upper()}\n"
            f"Duration         {self.snapshot.duration_seconds:.2f}s\n"
            f"Decoders Used    {self.snapshot.decode_count}\n"
            f"Artifacts Found  {self.snapshot.artifact_count}\n"
            f"IOC Extracted    {self.snapshot.ioc_count}"
        )

    def _top_findings_text(self) -> str:
        iocs = self.snapshot.iocs
        public_ips = len(iocs.get("ipv4_public", [])) + len(iocs.get("ipv4", []))
        hashes = len(iocs.get("hashes", []))
        high_entropy = sum(
            float(node.get("entropy", 0) or 0) >= 7.5 for node in self.snapshot.nodes
        )
        return (
            "[#73cfff]TOP FINDINGS[/#73cfff]\n\n"
            f"[#df69ba]●[/#df69ba] URLs                         {len(iocs.get('urls', [])):>3}\n"
            f"[#ff6b2f]●[/#ff6b2f] IP Addresses                  {public_ips:>3}\n"
            f"[#ffbb20]●[/#ffbb20] Email Addresses               {len(iocs.get('emails', [])):>3}\n"
            f"[#f4d02b]●[/#f4d02b] File Hashes                    {hashes:>3}\n"
            f"[#5ccdd0]●[/#5ccdd0] Interesting Strings           {len(self.snapshot.strings):>3}\n"
            f"[#8f9cff]●[/#8f9cff] Entropy High Regions          {high_entropy:>3}"
        )

    def _highlight_rows(self) -> list[tuple[str, str]]:
        rows: list[tuple[str, str]] = []
        decoders = []
        for node in self.snapshot.nodes:
            decoder = node.get("decoder_used")
            if decoder and decoder not in decoders:
                decoders.append(str(decoder))
        for decoder in decoders[:2]:
            rows.append((f"{decoder} Data", "green-highlight"))
        for detection in self.snapshot.detections[:2]:
            label = detection.get("name") or detection.get("rule_id") or "Detection"
            rows.append((str(label), "orange-highlight"))
        if self.snapshot.ioc_count:
            rows.append(("IOC Detected", "blue-highlight"))
        if any(float(node.get("entropy", 0) or 0) >= 7.5 for node in self.snapshot.nodes):
            rows.append(("High Entropy", "yellow-highlight"))
        if self.snapshot.assurance.get("verdict") == "SUSPICIOUS":
            rows.append(("Suspicious", "violet-highlight"))
        return rows[:5] or [("Awaiting Analysis", "blue-highlight")]

    def compose(self) -> ComposeResult:
        yield Label("LATEST ANALYSIS RESULTS", classes="panel-heading")
        with Horizontal(id="results-body"):
            yield Static(
                f"[#cbd6e0]{icons.DOCUMENT}[/#cbd6e0]  "
                f"[b]{markup_escape(self.snapshot.source_name)}[/b]\n\n"
                f"     {self.snapshot.source_size:,} bytes  •  "
                f"{self.snapshot.duration_seconds:.2f}s",
                id="artifact-card",
            )
            with TabbedContent(initial="summary-tab", id="results-tabs"):
                with TabPane("SUMMARY", id="summary-tab"):
                    with Vertical(id="summary-content"):
                        with Horizontal(id="analysis-summary-grid"):
                            yield Static(self._overview_text(), classes="result-card")
                            yield Static(self._top_findings_text(), classes="result-card")
                        with Vertical(id="detection-highlights"):
                            yield Label(
                                "DETECTION HIGHLIGHTS", classes="subsection-heading"
                            )
                            with Horizontal(id="highlight-row"):
                                for label, style in self._highlight_rows():
                                    yield Static(
                                        markup_escape(label),
                                        classes=f"highlight-chip {style}",
                                    )
                with TabPane(
                    f"DETECTIONS ({len(self.snapshot.detections)})",
                    id="detections-tab",
                ):
                    yield Static(
                        detections_text(self.snapshot), classes="scroll-result"
                    )
                with TabPane(
                    f"STRINGS ({len(self.snapshot.strings)})", id="strings-tab"
                ):
                    yield Static(strings_text(self.snapshot), classes="scroll-result")
                with TabPane(f"IOC ({self.snapshot.ioc_count})", id="iocs-tab"):
                    yield Static(iocs_text(self.snapshot), classes="scroll-result")
                with TabPane("HEX VIEW", id="hex-tab"):
                    yield Static(
                        hex_preview(
                            self.snapshot.decoded_output,
                            empty="No raw decoder output captured.",
                        ),
                        classes="scroll-result",
                    )


class DecoderPanel(Vertical):
    def __init__(self, decoder_rows: list[tuple[int, str, str]]):
        super().__init__(id="decoder-panel")
        self.decoder_rows = decoder_rows

    @staticmethod
    def option(index: int, label: str) -> Option:
        suffix = f"[#40d56b]{icons.DOT}[/#40d56b]"
        if index == 0:
            suffix = f"[#40d56b]{icons.CHECK}  {icons.DOT}[/#40d56b]"
        return Option(
            f"{index + 1:02d}   {markup_escape(label):<27} {suffix}",
            id=str(index),
        )

    def compose(self) -> ComposeResult:
        yield Label("DECODER WORKBENCH", classes="panel-heading")
        with Horizontal(id="decoder-toolbar"):
            yield Input(placeholder=f"{icons.SEARCH}  Search decoders…", id="decoder-search")
            yield Label(
                f"{len(self.decoder_rows)} Decoders Available",
                id="decoder-count",
                classes="count-label",
            )
        yield OptionList(
            *[
                self.option(index, label)
                for index, label, _ in self.decoder_rows
            ],
            id="decoder-list",
        )
        yield Static(
            f"…  View all decoders                              {icons.CHEVRON}",
            id="decoder-list-footer",
        )


class DecoderDetailsPanel(VerticalScroll):
    def __init__(self, label: str, description: str, snapshot: AnalysisSnapshot):
        super().__init__(id="decoder-details-panel")
        self.label = label
        self.description = description
        self.snapshot = snapshot

    def compose(self) -> ComposeResult:
        yield Label("DECODER DETAILS", classes="panel-heading")
        yield Static(
            f"[b]{markup_escape(self.label)}[/b]\n{markup_escape(self.description)}",
            id="decoder-description",
        )
        yield Label("INPUT", classes="detail-heading")
        preview = self.snapshot.input_preview or self.snapshot.source_name
        yield Static(
            f"{markup_escape(preview)}\n[#8fa2b4]{self.snapshot.source_size:,} bytes[/#8fa2b4]",
            id="decoder-input",
            classes="detail-box",
        )
        yield Label("OUTPUT", classes="detail-heading")
        yield Static(
            f"{decoded_text(self.snapshot)}\n"
            f"[#8fa2b4]{len(self.snapshot.decoded_output or b''):,} bytes[/#8fa2b4]",
            id="decoder-output",
        )
        status = "[#ff6b5c]Not Running[/#ff6b5c]"
        confidence = "--"
        if self.snapshot.decoder_success is True:
            status = "[#58df72]Successfully Decoded![/#58df72]"
            confidence = "1.00"
        elif self.snapshot.decoder_success is False:
            status = "[#ff6b5c]× Decode Failed[/#ff6b5c]"
            confidence = "0.00"
        yield Label("STATUS", classes="detail-heading")
        yield Static(
            f"{status}                         Confidence: {confidence}",
            id="decoder-status",
        )
        yield Label("ACTIONS", classes="detail-heading actions-heading")
        with Horizontal(id="decoder-actions"):
            yield Button(f"{icons.COPY}  Copy Output", id="copy-output")
            yield Button(f"{icons.SAVE}  Save Output", id="save-output")
            yield Button(
                f"{icons.RUN}  Run Decoder", id="run-decoder", variant="success"
            )


class SettingsPanel(VerticalScroll):
    def __init__(self, state: WorkbenchState):
        super().__init__(id="dynamic-view")
        self.state = state

    def compose(self) -> ComposeResult:
        yield Label("SETTINGS", classes="panel-heading")
        yield Label("Analysis profile")
        yield Select(
            [("Safe", "safe"), ("Fast", "fast"), ("Full", "full")],
            value=self.state.profile,
            id="profile-select",
        )
        yield Label("Offline mode")
        yield Switch(value=self.state.offline, id="offline-switch")
        yield Label("Aggressive auto-detect")
        yield Switch(value=self.state.aggressive, id="aggressive-switch")
        yield Static(
            "Settings are session-scoped. Titan remains offline by default.",
            classes="settings-note",
        )


class AnalystPanel(VerticalScroll):
    def __init__(
        self, answer: str = "Ask a grounded question about the active report."
    ):
        super().__init__(id="dynamic-view")
        self.answer = answer

    def compose(self) -> ComposeResult:
        yield Label("LOCAL AI ANALYST", classes="panel-heading")
        yield Static(
            "Deterministic and citation-grounded by default. No model or network is required.",
            classes="settings-note",
        )
        yield Input(
            value="Summarize this investigation.",
            placeholder="Ask about risk, decoding, IOCs, MITRE, or next steps…",
            id="analyst-question",
        )
        yield Button("Ask Analyst", id="ask-analyst", variant="primary")
        yield Static(
            markup_escape(self.answer),
            id="analyst-answer",
            classes="scroll-result",
        )
