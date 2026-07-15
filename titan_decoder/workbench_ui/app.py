from __future__ import annotations

from pathlib import Path
import binascii

try:
    from textual import on, work
    from textual.app import App, ComposeResult
    from textual.binding import Binding
    from textual.containers import Horizontal, Vertical
    from textual.widgets import (
        Button,
        Footer,
        Header,
        Input,
        OptionList,
        Select,
        Static,
        Switch,
    )
    from textual.widgets.option_list import Option
except ImportError as exc:  # pragma: no cover
    raise SystemExit(
        "Titan Forensic Workbench requires Textual. "
        "Install with: python -m pip install -e '.[workbench-ui]'"
    ) from exc

from .models import AnalysisSnapshot
from .services import WorkbenchServices
from .widgets import (
    DecoderDetailsPanel,
    DecoderPanel,
    InvestigationPanel,
    NavigationPanel,
    ResultsPanel,
    SettingsPanel,
    AnalystPanel,
    StatusCards,
)


class TitanWorkbenchApp(App):
    TITLE = "Titan Forensic Workbench"
    SUB_TITLE = "Offline · Deterministic · Evidence First"

    ROUTES = (
        "dashboard",
        "investigation",
        "decoders",
        "reports",
        "plugins",
        "settings",
        "correlation",
        "timeline",
        "analyst",
    )

    CSS = """
    Screen {
        background: #050b12;
        color: #d9e5ee;
    }

    Header {
        background: #08121c;
        color: #d9e5ee;
        border-bottom: solid #173346;
    }

    Footer {
        background: #08121c;
        color: #a9beca;
        border-top: solid #173346;
    }

    #application-body {
        height: 1fr;
    }

    #left-column {
        width: 30;
        min-width: 26;
        height: 1fr;
        padding: 1;
        background: #07111a;
        border-right: solid #173346;
    }

    #center-column {
        width: 1fr;
        height: 1fr;
        padding: 1;
        background: #050b12;
    }

    #right-column {
        width: 42;
        min-width: 34;
        height: 1fr;
        padding: 1;
        background: #07111a;
        border-left: solid #173346;
    }

    .panel-heading {
        color: #30bfff;
        text-style: bold;
        margin-bottom: 1;
    }

    .shortcuts-heading {
        margin-top: 1;
    }

    #navigation-list {
        height: 20;
        border: round #173346;
        background: #08121c;
    }

    OptionList > .option-list--option-highlighted {
        background: #0e3a58;
        color: #ffffff;
    }

    .shortcut-list {
        height: auto;
        border: round #173346;
        background: #08121c;
        padding: 1 2;
        color: #a9beca;
    }

    .brand-card {
        height: auto;
        border: round #173346;
        background: #08121c;
        padding: 1 2;
        margin-top: 1;
        color: #79d4ff;
    }

    #input-row {
        height: auto;
    }

    #evidence-input {
        width: 1fr;
    }

    #analyze-button {
        width: 16;
        margin-left: 1;
    }

    #drop-zone {
        height: 12;
        content-align: center middle;
        text-align: center;
        border: dashed #36586d;
        background: #08121c;
        color: #dce9f1;
        margin-top: 1;
        padding: 1;
    }

    #quick-start {
        height: auto;
        margin-top: 1;
    }

    #quick-start Button {
        width: 1fr;
        margin-right: 1;
    }

    #status-cards {
        height: 11;
        margin-top: 1;
    }

    .metric-card {
        width: 1fr;
        height: 10;
        padding: 1 2;
        margin-right: 1;
        background: #08121c;
    }

    .violet-card { border: round #8b5cf6; color: #d6c5ff; }
    .blue-card { border: round #2596d1; color: #bde9ff; }
    .green-card { border: round #24a65a; color: #bdf7cb; }
    .yellow-card { border: round #d39d12; color: #ffeca7; }

    #results-body {
        height: 1fr;
    }

    #artifact-card {
        width: 28;
        min-width: 22;
        height: 1fr;
        border: round #173346;
        background: #08121c;
        padding: 1 2;
        margin-right: 1;
    }

    #results-tabs {
        width: 1fr;
        height: 1fr;
        border: round #173346;
        background: #08121c;
    }

    Tabs {
        background: #08121c;
        color: #9db6c5;
    }

    Tab.-active {
        color: #42c8ff;
        text-style: bold;
    }

    .tab-columns {
        height: 1fr;
        padding: 1;
    }

    .result-card {
        width: 1fr;
        border: round #173346;
        padding: 1 2;
        margin-right: 1;
        background: #091722;
    }

    .scroll-result {
        height: 1fr;
        overflow-y: auto;
        padding: 1 2;
    }

    #decoder-search {
        margin-bottom: 1;
    }

    .count-label {
        color: #42c8ff;
        text-align: right;
        margin-bottom: 1;
    }

    #decoder-list {
        height: 24;
        border: round #173346;
        background: #08121c;
    }

    #decoder-description {
        border: round #173346;
        background: #08121c;
        padding: 1 2;
    }

    .detail-heading {
        color: #42c8ff;
        text-style: bold;
        margin-top: 1;
    }

    .detail-box {
        border-bottom: solid #173346;
        padding: 1 0;
        color: #b8cad5;
    }

    #decoder-output {
        height: 10;
        overflow-y: auto;
        border-bottom: solid #173346;
        padding: 1 0;
    }

    #decoder-status {
        color: #73e28a;
        padding: 1 0;
    }

    #decoder-actions {
        height: auto;
        margin-top: 1;
    }

    #decoder-actions Button {
        width: 1fr;
        margin-right: 1;
    }

    #settings-view {
        border: round #173346;
        background: #08121c;
        padding: 1 2;
    }

    .settings-note {
        color: #9db6c5;
        margin-top: 1;
    }

    .placeholder-view {
        border: round #173346;
        background: #08121c;
        padding: 2;
        height: 1fr;
    }
    """

    BINDINGS = [
        Binding("h", "show_dashboard", "Dashboard"),
        Binding("a", "focus_evidence", "Analyze"),
        Binding("d", "focus_decoders", "Decoders"),
        Binding("r", "show_reports", "Reports"),
        Binding("c", "show_correlation", "Correlation"),
        Binding("t", "show_timeline", "Timeline"),
        Binding("i", "show_analyst", "AI Analyst"),
        Binding("p", "show_plugins", "Plugins"),
        Binding("s", "show_settings", "Settings"),
        Binding("q", "quit", "Quit"),
    ]

    def __init__(self):
        super().__init__()
        self.services = WorkbenchServices()
        self.snapshot = AnalysisSnapshot()
        self.selected_decoder = 0
        self.input_mode = "auto"

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="application-body"):
            with Vertical(id="left-column"):
                yield NavigationPanel()
            with Vertical(id="center-column"):
                yield InvestigationPanel()
                plugins, errors = self.services.plugin_status()
                yield StatusCards(
                    self.services.state,
                    engine_version=self.services.engine_version(),
                    decoder_count=self.services.decoder_count(),
                    plugin_count=plugins,
                    plugin_errors=errors,
                    correlation_status=self.services.correlation_status(),
                    metrics=self.services.system_metrics(),
                )
                yield ResultsPanel(self.snapshot)
            with Vertical(id="right-column"):
                yield DecoderPanel(self.services.decoder_rows())
                label, description = self.services.decoder_details(self.selected_decoder)
                yield DecoderDetailsPanel(label, description, self.snapshot)
        yield Footer()

    def _replace_widget(self, selector: str, widget) -> None:
        current = self.query_one(selector)
        current.remove()
        if selector == "ResultsPanel":
            self.query_one("#center-column").mount(widget)
        elif selector == "DecoderDetailsPanel":
            self.query_one("#right-column").mount(widget)

    def refresh_results(self) -> None:
        self.query_one("#dynamic-view").remove()
        self.query_one("#center-column").mount(ResultsPanel(self.snapshot))

    def refresh_decoder_details(self) -> None:
        self.query_one(DecoderDetailsPanel).remove()
        label, description = self.services.decoder_details(self.selected_decoder)
        self.query_one("#right-column").mount(
            DecoderDetailsPanel(label, description, self.snapshot)
        )

    def _read_input(self) -> tuple[bytes, str]:
        raw = self.query_one("#evidence-input", Input).value.strip()
        if not raw:
            raise ValueError("Enter text, hex, or a file path first.")
        path = Path(raw.strip("'\"")).expanduser()
        if path.exists() and path.is_file():
            return path.read_bytes(), path.name
        if path.exists() and path.is_dir():
            raise IsADirectoryError(str(path))
        if self.input_mode == "hex":
            cleaned = raw.replace(" ", "").replace("\n", "")
            return binascii.unhexlify(cleaned), "hex input"
        return raw.encode("utf-8"), "pasted input"

    @on(Button.Pressed, "#analyze-button")
    def analyze_pressed(self) -> None:
        self.start_analysis()

    @on(Input.Submitted, "#evidence-input")
    def analyze_submitted(self) -> None:
        self.start_analysis()

    @work(thread=True, exclusive=True)
    def start_analysis(self) -> None:
        try:
            raw = self.call_from_thread(lambda: self.query_one("#evidence-input", Input).value.strip())
            candidate = Path(raw.strip("'\"")).expanduser() if raw else Path("__missing__")
            if raw and candidate.exists() and candidate.is_dir():
                snapshot = self.services.analyze_path(candidate)
            else:
                data, source_name = self.call_from_thread(self._read_input)
                snapshot = self.services.analyze(data, source_name)
        except Exception as exc:
            self.call_from_thread(self.notify, str(exc), severity="error")
            return
        self.snapshot = snapshot
        self.call_from_thread(self.refresh_results)
        self.call_from_thread(self.refresh_decoder_details)
        message = f"Analysis complete ({snapshot.batch_succeeded}/{snapshot.batch_total} files)" if snapshot.batch_total > 1 else "Analysis complete"
        if snapshot.batch_errors:
            message += f"; {len(snapshot.batch_errors)} failed"
        self.call_from_thread(self.notify, message, severity="information")

    @on(OptionList.OptionSelected, "#decoder-list")
    def decoder_selected(self, event: OptionList.OptionSelected) -> None:
        self.selected_decoder = int(event.option.id or "0")
        self.refresh_decoder_details()

    @on(Input.Changed, "#decoder-search")
    def decoder_search_changed(self, event: Input.Changed) -> None:
        needle = event.value.strip().lower()
        option_list = self.query_one("#decoder-list", OptionList)
        option_list.clear_options()
        rows = self.services.decoder_rows()
        for index, label, description in rows:
            if not needle or needle in label.lower() or needle in description.lower():
                option_list.add_option(Option(f"{index + 1:02d}  {label}", id=str(index)))

    @on(Button.Pressed, "#run-decoder")
    def run_decoder_pressed(self) -> None:
        self.start_decoder()

    @work(thread=True, exclusive=True)
    def start_decoder(self) -> None:
        try:
            data, source_name = self.call_from_thread(self._read_input)
            snapshot = self.services.run_decoder(self.selected_decoder, data, source_name)
        except Exception as exc:
            self.call_from_thread(self.notify, str(exc), severity="error")
            return
        self.snapshot = snapshot
        self.call_from_thread(self.refresh_results)
        self.call_from_thread(self.refresh_decoder_details)
        self.call_from_thread(self.notify, "Decoder finished", severity="information")

    @on(Button.Pressed, "#save-output")
    def save_output_pressed(self) -> None:
        if not self.snapshot.decoded_output:
            self.notify("No decoded output to save.", severity="warning")
            return
        destination = Path.cwd() / "titan-decoded-output.bin"
        destination.write_bytes(self.snapshot.decoded_output)
        self.notify(f"Saved {destination}", severity="information")

    @on(Button.Pressed, "#paste-action")
    def paste_mode(self) -> None:
        self.input_mode = "auto"
        self.query_one("#evidence-input", Input).focus()

    @on(Button.Pressed, "#hex-action")
    def hex_mode(self) -> None:
        self.input_mode = "hex"
        self.query_one("#evidence-input", Input).focus()
        self.notify("Hex input mode enabled.", severity="information")

    @on(Button.Pressed, "#file-action")
    def file_mode(self) -> None:
        self.input_mode = "auto"
        field = self.query_one("#evidence-input", Input)
        field.placeholder = "/path/to/evidence.bin"
        field.focus()

    @on(Button.Pressed, "#report-action")
    def load_report_pressed(self) -> None:
        reports = self.services.reports()
        if not reports:
            self.notify("No reports found.", severity="warning")
            return
        try:
            self.snapshot = self.services.load_report(reports[0])
        except Exception as exc:
            self.notify(str(exc), severity="error")
            return
        self.refresh_results()
        self.refresh_decoder_details()
        self.notify(f"Loaded {reports[0].name}", severity="information")

    @on(OptionList.OptionSelected, "#navigation-list")
    async def navigation_selected(self, event: OptionList.OptionSelected) -> None:
        route = event.option.id or "dashboard"
        if route == "dashboard":
            self.action_show_dashboard()
        elif route == "investigation":
            self.action_focus_evidence()
        elif route == "decoders":
            self.action_focus_decoders()
        elif route == "reports":
            await self.action_show_reports()
        elif route == "plugins":
            await self.action_show_plugins()
        elif route == "settings":
            await self.action_show_settings()
        elif route == "correlation":
            await self.action_show_correlation()
        elif route == "timeline":
            await self.action_show_timeline()
        elif route == "analyst":
            await self.action_show_analyst()

    def action_show_dashboard(self) -> None:
        self.query_one("#evidence-input", Input).focus()

    def action_focus_evidence(self) -> None:
        self.query_one("#evidence-input", Input).focus()

    def action_focus_decoders(self) -> None:
        self.query_one("#decoder-list", OptionList).focus()

    async def action_show_reports(self) -> None:
        reports = self.services.reports()
        lines = ["[b]REPORTS & EVIDENCE[/b]", ""]
        lines.extend(f"• {path.name}" for path in reports[:50])
        if not reports:
            lines.append("No reports found.")
        await self._show_center_overlay("\n".join(lines))

    async def action_show_plugins(self) -> None:
        count, errors = self.services.plugin_status()
        await self._show_center_overlay(
            "[b]PLUGIN MANAGER[/b]\n\n"
            f"Loaded plugins: {count}\n"
            f"Discovery errors: {errors}\n\n"
            "Plugin execution remains managed by Titan's Plugin SDK."
        )

    async def action_show_settings(self) -> None:
        await self._show_center_overlay_widget(SettingsPanel(self.services.state))

    async def action_show_correlation(self) -> None:
        from .presenters import correlation_text
        await self._show_center_overlay(
            "[b]CORRELATION ENGINE[/b]\n\n" + correlation_text(self.snapshot)
        )

    async def action_show_timeline(self) -> None:
        from .presenters import timeline_text
        await self._show_center_overlay(
            "[b]TIMELINE VIEW[/b]\n\n" + timeline_text(self.snapshot)
        )

    async def action_show_analyst(self) -> None:
        await self._show_center_overlay_widget(AnalystPanel())

    async def _show_center_overlay(self, text: str) -> None:
        await self._show_center_overlay_widget(
            Static(text, id="dynamic-view", classes="placeholder-view")
        )

    async def _show_center_overlay_widget(self, widget) -> None:
        current = self.query_one("#dynamic-view")
        await current.remove()
        await self.query_one("#center-column").mount(widget)

    @on(Button.Pressed, "#ask-analyst")
    def ask_analyst_pressed(self) -> None:
        question = self.query_one("#analyst-question", Input).value.strip()
        if not question:
            self.notify("Enter a question.", severity="warning")
            return
        try:
            response = self.services.analyst_answer(self.snapshot, question)
        except Exception as exc:
            self.notify(str(exc), severity="error")
            return
        answer = response.get("answer", "")
        meta = (
            f"\n\nbackend={response.get('backend')} · intent={response.get('intent')} "
            f"· fallback={response.get('fallback_used')}"
        )
        self.query_one("#analyst-answer", Static).update(answer + meta)

    @on(Select.Changed, "#profile-select")
    def profile_changed(self, event: Select.Changed) -> None:
        if event.value:
            self.services.update_state(profile=str(event.value))
            self.notify(f"Profile: {event.value}", severity="information")

    @on(Switch.Changed, "#offline-switch")
    def offline_changed(self, event: Switch.Changed) -> None:
        self.services.update_state(offline=event.value)

    @on(Switch.Changed, "#aggressive-switch")
    def aggressive_changed(self, event: Switch.Changed) -> None:
        self.services.update_state(aggressive=event.value)


def main() -> int:
    TitanWorkbenchApp().run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
