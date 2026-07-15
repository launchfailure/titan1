from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import (
    Button,
    DataTable,
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
    strings_text,
    summary_text,
)


class NavigationPanel(Vertical):
    def compose(self) -> ComposeResult:
        yield Label("NAVIGATION", classes="panel-heading")
        yield OptionList(
            Option("Dashboard               [H]", id="dashboard"),
            Option("Investigation Workspace [A]", id="investigation"),
            Option("Decoder Workbench       [D]", id="decoders"),
            Option("Reports & Evidence      [R]", id="reports"),
            Option("Correlation Engine      [C]", id="correlation"),
            Option("Timeline View           [T]", id="timeline"),
            Option("AI Analyst              [I]", id="analyst"),
            Option("Plugin Manager          [P]", id="plugins"),
            Option("Settings                [S]", id="settings"),
            id="navigation-list",
        )
        yield Label("SHORTCUTS", classes="panel-heading shortcuts-heading")
        yield Static(
            "H  Dashboard\n"
            "A  Analyze Evidence\n"
            "D  Decoder Workbench\n"
            "R  Reports & Evidence\n"
            "C  Correlation\n"
            "T  Timeline\n"
            "I  AI Analyst\n"
            "P  Plugins\n"
            "S  Settings\n"
            "?  Help\n"
            "Q  Quit",
            classes="shortcut-list",
        )
        yield Static(
            "[b]TITAN[/b]\n"
            "[#2aa9ff]DETERMINISTIC ANALYSIS[/#2aa9ff]\n"
            "POWERED BY TITAN ENGINE",
            classes="brand-card",
        )


class InvestigationPanel(Vertical):
    def compose(self) -> ComposeResult:
        yield Label("INVESTIGATION WORKSPACE", classes="panel-heading")
        with Horizontal(id="input-row"):
            yield Input(
                placeholder="Paste text, hex, or a file/folder path…",
                id="evidence-input",
            )
            yield Button("Analyze", id="analyze-button", variant="primary")
        yield Static(
            "DROP FILES OR FOLDERS HERE\n\n"
            "Paste a path above, paste raw data, or press [A] to focus input.\n\n"
            "Folder paths are processed as a deterministic multi-file queue.\nReports are saved locally; failures are non-fatal and summarized.",
            id="drop-zone",
        )
        with Horizontal(id="quick-start"):
            yield Button("Paste text/data", id="paste-action")
            yield Button("Enter hex", id="hex-action")
            yield Button("Load file", id="file-action")
            yield Button("Load report", id="report-action")


class StatusCards(Vertical):
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
        super().__init__()
        self.state = state
        self.engine_version = engine_version
        self.decoder_count = decoder_count
        self.plugin_count = plugin_count
        self.plugin_errors = plugin_errors
        self.correlation_status = correlation_status
        self.metrics = metrics

    def compose(self) -> ComposeResult:
        plugin_value = str(self.plugin_count)
        if self.plugin_errors:
            plugin_value += f" ({self.plugin_errors} errors)"
        with Horizontal(id="status-cards"):
            yield Static(
                "[b]SESSION INFO[/b]\n\n"
                "Artifacts       session\n"
                "Analyses        local\n"
                "Evidence        private\n"
                "Storage         local",
                classes="metric-card violet-card",
            )
            yield Static(
                "[b]SYSTEM STATUS[/b]\n\n"
                f"Decoders       {self.decoder_count}\n"
                f"Plugins        {plugin_value}\n"
                f"Correlation    {self.correlation_status}\n"
                "Telemetry      none",
                classes="metric-card blue-card",
            )
            yield Static(
                "[b]ENGINE STATUS[/b]\n\n"
                f"Engine         v{self.engine_version}\n"
                f"Profile        {self.state.profile.upper()}\n"
                f"Aggressive     {'ON' if self.state.aggressive else 'OFF'}\n"
                f"Network        {'OFFLINE' if self.state.offline else 'ONLINE'}",
                classes="metric-card green-card",
            )
            yield Static(
                "[b]RESOURCE USAGE[/b]\n\n"
                f"CPU            {self.metrics['cpu']}\n"
                f"Memory         {self.metrics['memory']}\n"
                f"Disk           {self.metrics['disk']}\n"
                f"Workers        {self.metrics['workers']}",
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
                f"[b]{self.snapshot.source_name}[/b]\n"
                f"{self.snapshot.source_size:,} bytes\n"
                f"{self.snapshot.duration_seconds:.2f}s",
                id="artifact-card",
            )
            with TabbedContent(initial="summary-tab", id="results-tabs"):
                with TabPane("SUMMARY", id="summary-tab"):
                    with Horizontal(classes="tab-columns"):
                        yield Static(summary_text(self.snapshot), classes="result-card")
                        yield Static(findings_text(self.snapshot), classes="result-card")
                with TabPane(f"DETECTIONS ({len(self.snapshot.detections)})", id="detections-tab"):
                    yield Static(detections_text(self.snapshot), classes="scroll-result")
                with TabPane(f"STRINGS ({len(self.snapshot.strings)})", id="strings-tab"):
                    yield Static(strings_text(self.snapshot), classes="scroll-result")
                with TabPane(f"IOCS ({self.snapshot.ioc_count})", id="iocs-tab"):
                    yield Static(iocs_text(self.snapshot), classes="scroll-result")
                with TabPane("DECODE TREE", id="tree-tab"):
                    yield Static(decode_tree_text(self.snapshot), classes="scroll-result")
                with TabPane("HEX VIEW", id="hex-tab"):
                    yield Static(hex_preview(self.snapshot.decoded_output), classes="scroll-result")


class DecoderPanel(Vertical):
    def __init__(self, decoder_rows: list[tuple[int, str, str]]):
        super().__init__()
        self.decoder_rows = decoder_rows

    def compose(self) -> ComposeResult:
        yield Label("DECODER WORKBENCH", classes="panel-heading")
        yield Input(placeholder="Search decoders…", id="decoder-search")
        yield Label(f"{len(self.decoder_rows)} Decoders Available", classes="count-label")
        yield OptionList(
            *[
                Option(f"{index + 1:02d}  {label}", id=str(index))
                for index, label, _ in self.decoder_rows
            ],
            id="decoder-list",
        )


class DecoderDetailsPanel(Vertical):
    def __init__(self, label: str, description: str, snapshot: AnalysisSnapshot):
        super().__init__()
        self.label = label
        self.description = description
        self.snapshot = snapshot

    def compose(self) -> ComposeResult:
        yield Label("DECODER DETAILS", classes="panel-heading")
        yield Static(f"[b]{self.label}[/b]\n{self.description}", id="decoder-description")
        yield Label("INPUT", classes="detail-heading")
        yield Static(
            f"{self.snapshot.source_name}\n{self.snapshot.source_size:,} bytes",
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
    def __init__(self, answer: str = "Ask a grounded question about the active report."):
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
        yield Static(self.answer, id="analyst-answer", classes="scroll-result")
