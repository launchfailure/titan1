from __future__ import annotations

from datetime import datetime
from pathlib import Path

from textual.app import ComposeResult
from textual.containers import Horizontal, HorizontalScroll, Vertical, VerticalScroll
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

from .models import AnalysisSnapshot, WorkbenchState
from .presenters import (
    decode_tree_text,
    decoded_text,
    detections_text,
    findings_text,
    hex_preview,
    iocs_text,
    markup_escape,
    strings_text,
    summary_text,
)


class WorkbenchHeader(Horizontal):
    """Compact application chrome inspired by the forensic workbench mock-up."""

    def __init__(self, state: WorkbenchState, *, version: str, session_id: str):
        super().__init__(id="workbench-header")
        self.state = state
        self.version = version
        self.session_id = session_id

    def compose(self) -> ComposeResult:
        yield Static(
            "[#2aa9ff]◈[/#2aa9ff] [b]TITAN FORENSIC WORKBENCH[/b] "
            f"[dim]v{markup_escape(self.version)}[/dim]",
            id="workbench-title",
        )
        with Horizontal(id="header-status"):
            yield Static(id="profile-chip", classes="status-chip profile-chip")
            yield Static(id="network-chip", classes="status-chip network-chip")
            yield Static(id="aggressive-chip", classes="status-chip aggressive-chip")
        yield Static(id="session-clock")

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
            f"SESSION: {self.session_id}  ·  {datetime.now():%H:%M:%S}"
        )


class WorkbenchStatusBar(Horizontal):
    """A small status strip that leaves the workspace more vertical room."""

    def __init__(self, state: WorkbenchState):
        super().__init__(id="workbench-status-bar")
        self.state = state

    def compose(self) -> ComposeResult:
        yield Static("[#36d277]●[/#36d277] Ready", id="footer-state")
        yield Static(
            f"Working directory: {markup_escape(Path.cwd())}",
            id="footer-working-directory",
        )
        yield Static(id="footer-mode")

    def on_mount(self) -> None:
        self.refresh_state()

    def refresh_state(self, state: WorkbenchState | None = None) -> None:
        if state is not None:
            self.state = state
        mode = "Offline mode" if self.state.offline else "Online mode"
        self.query_one("#footer-mode", Static).update(f"{mode}  ·  ? Help  ·  Q Quit")


class NavigationPanel(VerticalScroll):
    def __init__(self):
        super().__init__(id="navigation-panel")

    def compose(self) -> ComposeResult:
        yield Label("NAVIGATION", classes="panel-heading")
        yield OptionList(
            Option("⌂  Dashboard", id="dashboard"),
            Option("⌕  Analyze Input", id="investigation"),
            Option("◫  Decoders", id="decoders"),
            Option("▤  Reports Browser", id="reports"),
            Option("◎  Correlation", id="correlation"),
            Option("↦  Timeline View", id="timeline"),
            Option("✦  Analyst", id="analyst"),
            Option("◆  Plugins", id="plugins"),
            Option("⚙  Settings", id="settings"),
            Option("?  Help & Keys", id="help"),
            id="navigation-list",
        )
        yield Label("SHORTCUTS", classes="panel-heading shortcuts-heading")
        yield Static(
            "H  Dashboard\n"
            "A  Analyze Input\n"
            "D  Decoders\n"
            "R  Reports Browser\n"
            "S  Settings\n"
            "Q  Quit",
            classes="shortcut-list",
        )
        yield Static("", id="navigation-spacer")
        yield Static(
            "[#2aa9ff]◈[/#2aa9ff] [b]TITAN[/b]\n"
            "[#2aa9ff]DETERMINISTIC CORE[/#2aa9ff]\n"
            "[dim]LOCAL · PRIVATE[/dim]",
            classes="brand-card",
        )


class InvestigationPanel(Vertical):
    def __init__(self):
        super().__init__(id="investigation-panel")

    def compose(self) -> ComposeResult:
        yield Label("INVESTIGATION WORKSPACE", classes="panel-heading")
        with Horizontal(id="input-row"):
            yield Input(
                placeholder="Paste text, hex, or a file/folder path…",
                id="evidence-input",
            )
            yield Button("Analyze", id="analyze-button", variant="primary")
        with Horizontal(id="investigation-body"):
            yield Static(
                "[#79d4ff]⇧[/#79d4ff]\n"
                "[b]DROP FILE OR FOLDER PATH HERE[/b]\n"
                "[dim]or press A to focus the evidence input[/dim]\n\n"
                "Raw text, hex, files, and deterministic folder queues are supported.",
                id="drop-zone",
            )
            with Vertical(id="quick-start"):
                yield Label("QUICK START", classes="subsection-heading")
                yield OptionList(
                    Option("01  Paste text / data", id="paste"),
                    Option("02  Enter hex string", id="hex"),
                    Option("03  Load file or folder", id="file"),
                    Option("04  Open recent report", id="report"),
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
    ):
        super().__init__(id="status-cards")
        self.state = state
        self.engine_version = engine_version
        self.decoder_count = decoder_count
        self.plugin_count = plugin_count
        self.plugin_errors = plugin_errors
        self.correlation_status = correlation_status
        self.metrics = metrics

    def _engine_status_text(self) -> str:
        return (
            "[b]ENGINE STATUS[/b]\n"
            f"Engine      v{self.engine_version}\n"
            f"Profile     {self.state.profile.upper()}\n"
            f"Aggressive  {'ON' if self.state.aggressive else 'OFF'}\n"
            f"Network     {'OFFLINE' if self.state.offline else 'ONLINE'}"
        )

    def refresh_state(self, state: WorkbenchState) -> None:
        self.state = state
        self.query_one("#engine-status-card", Static).update(self._engine_status_text())

    def compose(self) -> ComposeResult:
        plugin_value = str(self.plugin_count)
        if self.plugin_errors:
            plugin_value = f"{self.plugin_count}/{self.plugin_errors} err"
        correlation_value = self.correlation_status
        if correlation_value == "not initialized":
            correlation_value = "idle"
        yield Static(
            "[b]SESSION INFO[/b]\n"
            "Workspace   local\n"
            "Evidence    private\n"
            "Reports     local\n"
            "Storage     isolated",
            classes="metric-card violet-card",
        )
        yield Static(
            "[b]SYSTEM STATUS[/b]\n"
            f"Decoders    {self.decoder_count}\n"
            f"Plugins     {plugin_value}\n"
            f"Correlation {correlation_value}\n"
            "Telemetry   none",
            classes="metric-card blue-card",
        )
        yield Static(
            self._engine_status_text(),
            id="engine-status-card",
            classes="metric-card green-card",
        )
        yield Static(
            "[b]RESOURCE USAGE[/b]\n"
            f"CPU         {self.metrics['cpu']}\n"
            f"Memory      {self.metrics['memory']}\n"
            f"Disk        {self.metrics['disk']}\n"
            f"Workers     {self.metrics['workers']}",
            classes="metric-card yellow-card",
        )


class ResultsPanel(Vertical):
    def __init__(self, snapshot: AnalysisSnapshot):
        super().__init__(id="dynamic-view")
        self.snapshot = snapshot

    def compose(self) -> ComposeResult:
        yield Label("LATEST ANALYSIS RESULTS", classes="panel-heading")
        with Horizontal(id="results-body"):
            yield Static(
                f"[b]{markup_escape(self.snapshot.source_name)}[/b]\n"
                f"{self.snapshot.source_size:,} bytes\n"
                f"{self.snapshot.duration_seconds:.2f}s",
                id="artifact-card",
            )
            with TabbedContent(initial="summary-tab", id="results-tabs"):
                with TabPane("SUMMARY", id="summary-tab"):
                    with Horizontal(classes="tab-columns"):
                        yield Static(summary_text(self.snapshot), classes="result-card")
                        yield Static(
                            findings_text(self.snapshot), classes="result-card"
                        )
                with TabPane(
                    f"DETECTIONS ({len(self.snapshot.detections)})", id="detections-tab"
                ):
                    yield Static(
                        detections_text(self.snapshot), classes="scroll-result"
                    )
                with TabPane(
                    f"STRINGS ({len(self.snapshot.strings)})", id="strings-tab"
                ):
                    yield Static(strings_text(self.snapshot), classes="scroll-result")
                with TabPane(f"IOCS ({self.snapshot.ioc_count})", id="iocs-tab"):
                    yield Static(iocs_text(self.snapshot), classes="scroll-result")
                with TabPane("DECODE TREE", id="tree-tab"):
                    yield Static(
                        decode_tree_text(self.snapshot), classes="scroll-result"
                    )
                with TabPane("HEX VIEW", id="hex-tab"):
                    yield Static(
                        hex_preview(
                            self.snapshot.decoded_output,
                            empty=(
                                "No raw decoder output captured.\n"
                                "Hex view shows bytes from a manual decoder run — "
                                "pick a decoder on the right and press Run Decoder.\n"
                                "Decoded previews from an analysis are in the "
                                "DECODE TREE tab."
                            ),
                        ),
                        classes="scroll-result",
                    )


class DecoderPanel(Vertical):
    def __init__(self, decoder_rows: list[tuple[int, str, str]]):
        super().__init__(id="decoder-panel")
        self.decoder_rows = decoder_rows

    def compose(self) -> ComposeResult:
        yield Label("DECODER WORKBENCH", classes="panel-heading")
        with Horizontal(id="decoder-toolbar"):
            yield Input(placeholder="Search decoders…", id="decoder-search")
            yield Label(
                f"{len(self.decoder_rows)} available",
                id="decoder-count",
                classes="count-label",
            )
        yield OptionList(
            *[
                Option(
                    f"{index + 1:02d}  {markup_escape(label)}  [#36d277]●[/#36d277]",
                    id=str(index),
                )
                for index, label, _ in self.decoder_rows
            ],
            id="decoder-list",
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
        yield Static(
            f"{markup_escape(self.snapshot.source_name)}\n"
            f"{self.snapshot.source_size:,} bytes",
            classes="detail-box",
        )
        yield Label("OUTPUT", classes="detail-heading")
        yield Static(decoded_text(self.snapshot), id="decoder-output")
        status = "Not run"
        if self.snapshot.decoder_success is True:
            status = "✓ Successfully decoded"
        elif self.snapshot.decoder_success is False:
            status = "✗ Decode failed"
        yield Label("STATUS", classes="detail-heading")
        yield Static(status, id="decoder-status")
        with Horizontal(id="decoder-actions"):
            yield Button("Save Output", id="save-output")
            yield Button("Run Decoder", id="run-decoder", variant="success")


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
