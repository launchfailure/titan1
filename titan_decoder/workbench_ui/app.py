from __future__ import annotations

import binascii
import os
import re
from datetime import datetime
from hashlib import sha256
from pathlib import Path
from urllib.parse import unquote, urlparse

try:
    from textual import on, work
    from textual.app import App, ComposeResult
    from textual.binding import Binding
    from textual.containers import Horizontal, Vertical, VerticalScroll
    from textual.events import Click, Paste, Resize
    from textual.widgets import (
        Button,
        Input,
        OptionList,
        Select,
        Static,
        Switch,
    )
except ImportError as exc:  # pragma: no cover
    raise SystemExit(
        "Titan Forensic Workbench requires Textual. "
        "Install with: python -m pip install -e '.[workbench-ui]'"
    ) from exc

from .models import AnalysisSnapshot
from .presenters import markup_escape
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
    WorkbenchHeader,
    WorkbenchStatusBar,
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
        "help",
    )

    CSS = """
    Screen {
        background: #030912;
        color: #d7e3ed;
    }

    #workbench-header {
        height: 4;
        background: #06101a;
        border-bottom: solid #173346;
        padding: 0 1;
    }

    #workbench-title {
        width: 1fr;
        height: 3;
        content-align: left middle;
        color: #e7f1f7;
    }

    #header-status {
        width: auto;
        height: 3;
        align: center middle;
    }

    .status-chip {
        width: auto;
        height: 3;
        padding: 0 1;
        margin-right: 1;
        content-align: center middle;
        background: #08131f;
    }

    .profile-chip {
        color: #77df92;
        border: solid #214b34;
    }

    .network-chip {
        color: #7ecfff;
        border: solid #1b4059;
    }

    .aggressive-chip {
        color: #f0ca70;
        border: solid #4f421d;
    }

    #session-clock {
        width: 30;
        height: 3;
        content-align: right middle;
        color: #9cb1bf;
    }

    #workbench-status-bar {
        height: 2;
        padding: 0 1;
        background: #06101a;
        color: #9fb3c0;
        border-top: solid #173346;
    }

    #footer-state {
        width: 16;
        height: 1;
    }

    #footer-working-directory {
        width: 1fr;
        height: 1;
    }

    #footer-mode {
        width: auto;
        height: 1;
        text-align: right;
    }

    #application-body {
        height: 1fr;
    }

    #left-column {
        width: 27;
        min-width: 24;
        height: 1fr;
        padding: 0 1;
        background: #050e17;
        border-right: solid #173346;
    }

    #center-column {
        width: 1fr;
        height: 1fr;
        padding: 0 1;
        background: #030912;
    }

    #right-column {
        width: 42;
        min-width: 36;
        height: 1fr;
        padding: 0 1;
        background: #050e17;
        border-left: solid #173346;
    }

    Screen.compact-layout #left-column {
        width: 23;
        min-width: 23;
    }

    Screen.compact-layout #right-column {
        width: 34;
        min-width: 34;
    }

    Screen.compact-layout #quick-start {
        width: 28;
    }

    Screen.compact-layout #session-clock {
        display: none;
    }

    .panel-heading {
        color: #30bfff;
        text-style: bold;
        height: 1;
    }

    .subsection-heading {
        height: 1;
        padding: 0 1;
        color: #d7e3ed;
        text-style: bold;
    }

    #navigation-panel {
        height: 1fr;
    }

    .shortcuts-heading {
        margin-top: 1;
    }

    #navigation-list {
        height: 18;
        min-height: 12;
        border: round #173346;
        background: #07121e;
    }

    OptionList > .option-list--option-highlighted {
        background: #0b3a5a;
        color: #ffffff;
        text-style: bold;
    }

    .shortcut-list {
        height: 8;
        border: round #173346;
        background: #07121e;
        padding: 0 1;
        color: #a9beca;
    }

    #navigation-spacer {
        height: 1fr;
    }

    .brand-card {
        height: 5;
        border: round #173346;
        background: #07121e;
        padding: 0 1;
        margin-top: 1;
        color: #79d4ff;
    }

    InvestigationPanel,
    ResultsPanel,
    DecoderPanel,
    DecoderDetailsPanel {
        border: round #173346;
        background: #06101a;
        padding: 0 1;
    }

    InvestigationPanel {
        height: 15;
        min-height: 15;
        margin-bottom: 1;
    }

    #input-row {
        height: 3;
    }

    #evidence-input {
        width: 1fr;
    }

    #analyze-button {
        width: 12;
        margin-left: 1;
    }

    #investigation-body {
        height: 9;
    }

    #drop-zone {
        width: 1fr;
        height: 9;
        content-align: center middle;
        text-align: center;
        border: dashed #36586d;
        background: #07121e;
        color: #dce9f1;
        padding: 1;
    }

    #quick-start {
        width: 32;
        height: 9;
        margin-left: 1;
        border: solid #173346;
        background: #07121e;
    }

    #quick-start-list {
        height: 1fr;
        background: #07121e;
        border-top: solid #173346;
    }

    StatusCards {
        height: 7;
        min-height: 7;
        margin-bottom: 1;
    }

    .metric-card {
        width: 24%;
        min-width: 22;
        height: 7;
        padding: 0 1;
        margin-right: 1;
        background: #07121e;
    }

    .violet-card { border: round #8b5cf6; color: #d6c5ff; }
    .blue-card { border: round #2596d1; color: #bde9ff; }
    .green-card { border: round #24a65a; color: #bdf7cb; }
    .yellow-card { border: round #d39d12; color: #ffeca7; }

    ResultsPanel {
        height: 1fr;
        min-height: 22;
    }

    #results-body {
        height: 1fr;
    }

    #artifact-card {
        width: 24;
        min-width: 19;
        height: 1fr;
        border: round #173346;
        background: #07121e;
        padding: 1;
        margin-right: 1;
    }

    #results-tabs {
        width: 1fr;
        height: 1fr;
        border: round #173346;
        background: #07121e;
    }

    Tabs {
        background: #07121e;
        color: #9db6c5;
    }

    Tab.-active {
        color: #42c8ff;
        text-style: bold;
    }

    .tab-columns {
        height: 1fr;
        padding: 0;
    }

    .result-card {
        width: 1fr;
        border: round #173346;
        padding: 1;
        margin-right: 1;
        background: #081722;
    }

    .scroll-result {
        height: 1fr;
        overflow-y: auto;
        padding: 1;
    }

    DecoderPanel {
        height: 1fr;
        min-height: 22;
        margin-bottom: 1;
    }

    #decoder-toolbar {
        height: 3;
    }

    #decoder-search {
        width: 1fr;
    }

    .count-label {
        width: 13;
        height: 3;
        color: #42c8ff;
        text-align: right;
        content-align: right middle;
    }

    #decoder-list {
        height: 1fr;
        border: round #173346;
        background: #07121e;
    }

    DecoderDetailsPanel {
        height: 23;
        min-height: 23;
    }

    #decoder-description {
        height: auto;
        min-height: 3;
        border-bottom: solid #173346;
        padding: 0 1;
    }

    .detail-heading {
        color: #42c8ff;
        text-style: bold;
        height: 1;
    }

    .detail-box {
        height: 2;
        border-bottom: solid #173346;
        padding: 0 1;
        color: #b8cad5;
    }

    #decoder-output {
        height: 5;
        overflow-y: auto;
        border-bottom: solid #173346;
        padding: 0 1;
    }

    #decoder-status {
        color: #73e28a;
        height: 1;
        padding: 0 1;
    }

    #decoder-actions {
        height: 3;
    }

    #decoder-actions Button {
        width: 1fr;
    }

    #save-output {
        margin-right: 1;
    }

    #settings-view {
        border: round #173346;
        background: #07121e;
        padding: 1;
    }

    .settings-note {
        color: #9db6c5;
        margin-top: 1;
    }

    .placeholder-view {
        border: round #173346;
        background: #06101a;
        padding: 1;
        height: 1fr;
        min-height: 22;
    }

    /* Approved 1536×1024 forensic-workbench layout overrides. */
    Screen {
        background: #050b13;
        color: #dce4ec;
    }

    #workbench-header {
        height: 4;
        background: #050b13;
        border-bottom: solid #142737;
        padding: 0 1;
    }

    #workbench-brand {
        width: 35%;
        height: 3;
    }

    #brand-shield {
        width: 6;
        height: 3;
        content-align: center middle;
        text-align: center;
        text-style: bold;
        color: #28b8ff;
    }

    #workbench-title {
        width: 1fr;
        height: 3;
        content-align: left middle;
        color: #f0f4f8;
    }

    #header-status {
        width: 34%;
        height: 3;
        align: center middle;
    }

    .status-chip {
        height: 3;
        width: auto;
        min-width: 15;
        padding: 0 1;
        margin-right: 1;
        background: #08121d;
        content-align: center middle;
        text-align: center;
        border: round #1b3446;
    }

    .profile-chip { color: #55e17d; border: round #1d4433; }
    .network-chip { color: #70cfff; border: round #1a3b53; }
    .aggressive-chip { color: #f0c84d; border: round #4b3d1b; }

    #header-right {
        width: 31%;
        height: 3;
        align: right middle;
    }

    #session-clock {
        width: 1fr;
        height: 3;
        content-align: right middle;
        color: #a7b3c1;
        text-align: right;
        padding-right: 1;
    }

    .window-control {
        width: 5;
        min-width: 5;
        height: 3;
        margin-left: 1;
        padding: 0;
        border: round #26394b;
        background: #07111c;
        color: #9ba9b8;
    }

    .window-control:hover { background: #102133; color: #e2e9ef; }
    .close-control { border: round #873528; color: #ff6a55; }
    .close-control:hover { background: #421812; color: #ff8573; }

    #application-body {
        height: 1fr;
        padding: 1 1 0 1;
        background: #050b13;
    }

    #left-column {
        width: 15.5%;
        min-width: 26;
        height: 1fr;
        padding: 0;
        margin-right: 1;
        background: #050b13;
        border: none;
    }

    #center-column {
        width: 1fr;
        height: 1fr;
        padding: 0;
        margin-right: 1;
        background: #050b13;
        scrollbar-size: 1 1;
    }

    #right-column {
        width: 26%;
        min-width: 43;
        height: 1fr;
        padding: 0;
        background: #050b13;
        border: none;
        scrollbar-size: 1 1;
    }

    .panel-heading {
        height: 2;
        padding: 0 1;
        color: #37bdff;
        text-style: bold;
        content-align: left middle;
    }

    .subsection-heading {
        height: 2;
        padding: 0 1;
        color: #d8e0e8;
        text-style: bold;
        content-align: left middle;
    }

    #navigation-panel {
        height: 1fr;
        background: #050b13;
        scrollbar-size: 0 0;
    }

    .side-card {
        border: round #1b3040;
        background: #09131f;
    }

    #navigation-card {
        height: 28;
        margin-bottom: 1;
    }

    #shortcuts-card {
        height: 19;
        margin-bottom: 1;
    }

    #navigation-list {
        height: 1fr;
        padding: 0;
        border: none;
        background: #09131f;
        color: #d6dee7;
        scrollbar-size: 0 0;
    }

    #navigation-list > .option-list--option {
        padding: 0 1;
        color: #c8d1dc;
    }

    #navigation-list > .option-list--option-highlighted {
        background: #102a43;
        color: #ffffff;
        text-style: bold;
        border-left: solid #35b9ff;
        border-right: solid #35b9ff;
    }

    .shortcut-list {
        height: 1fr;
        border: none;
        background: #09131f;
        padding: 0 1;
        color: #9eacbb;
    }

    #navigation-spacer { height: 1fr; }

    .brand-card {
        height: 9;
        min-height: 9;
        margin: 0;
        border: round #1b3040;
        background: #07111c;
        padding: 2 2;
        color: #79d4ff;
        content-align: left middle;
    }

    InvestigationPanel,
    ResultsPanel,
    DecoderPanel,
    DecoderDetailsPanel {
        border: round #1a3040;
        background: #08121e;
        padding: 0;
    }

    InvestigationPanel {
        height: 20;
        min-height: 20;
        margin-bottom: 1;
    }

    #input-row {
        display: none;
        height: 3;
        margin: 0 1;
    }

    InvestigationPanel.input-active #input-row { display: block; }
    InvestigationPanel.input-active #investigation-body { height: 12; }

    #evidence-input { width: 1fr; }
    #analyze-button { width: 12; margin-left: 1; }

    #investigation-body {
        height: 16;
        padding: 1 2;
        border-top: solid #142737;
        background: #08121e;
    }

    #drop-zone {
        width: 62%;
        height: 14;
        padding: 1;
        margin-right: 2;
        border: dashed #40586b;
        background: #08131f;
        color: #dce3eb;
        content-align: center middle;
        text-align: center;
    }

    #quick-start {
        width: 38%;
        height: 14;
        margin: 0;
        border: round #1b3040;
        background: #08131f;
    }

    #quick-start-list {
        height: 1fr;
        border: none;
        border-top: solid #1b3040;
        background: #08131f;
        color: #d6dee7;
        scrollbar-size: 0 0;
    }

    #quick-start-list > .option-list--option {
        padding: 1 1;
        color: #d6dee7;
        border-bottom: solid #172939;
    }

    #quick-start-list > .option-list--option-highlighted {
        background: #10243a;
        color: #ffffff;
    }

    StatusCards {
        height: 12;
        min-height: 12;
        margin-bottom: 1;
        scrollbar-size: 0 0;
    }

    .metric-card {
        width: 1fr;
        min-width: 24;
        height: 12;
        margin-right: 1;
        padding: 1 2;
        background: #09131f;
        color: #d8e1e9;
    }

    .metric-card:last-of-type { margin-right: 0; }
    .violet-card { border: round #8845c7; }
    .blue-card { border: round #2278af; }
    .green-card { border: round #28984d; }
    .yellow-card { border: round #9e8412; }

    ResultsPanel {
        height: 1fr;
        min-height: 24;
    }

    #results-body {
        height: 1fr;
        padding: 0 1 1 1;
        border-top: solid #142737;
    }

    #artifact-card {
        width: 34%;
        min-width: 25;
        height: 1fr;
        margin-right: 1;
        padding: 2;
        border: round #1a3040;
        background: #091521;
        color: #dce3eb;
    }

    #results-tabs {
        width: 1fr;
        height: 1fr;
        border: round #1a3040;
        background: #08131f;
    }

    Tabs {
        height: 3;
        background: #08131f;
        color: #8fb6d0;
        border-bottom: solid #173044;
    }

    Tab {
        height: 2;
        padding: 0 2;
        color: #8fb6d0;
    }

    Tab.-active {
        color: #6ecfff;
        background: #08131f;
        text-style: bold;
        border-bottom: heavy #2db6ff;
    }

    #summary-content { height: 1fr; padding: 1; }

    #analysis-summary-grid {
        height: 1fr;
        min-height: 12;
    }

    .result-card {
        width: 1fr;
        height: 1fr;
        margin-right: 1;
        padding: 1 2;
        border: round #172b3a;
        background: #0a1723;
        color: #d6dfe8;
    }

    .result-card:last-of-type { margin-right: 0; }

    #detection-highlights {
        height: 6;
        margin-top: 1;
        padding: 0 1;
        border: round #172b3a;
        background: #091521;
    }

    #highlight-row {
        height: 3;
        align: left middle;
    }

    .highlight-chip {
        width: auto;
        height: 3;
        margin-right: 1;
        padding: 0 1;
        content-align: center middle;
        background: #0c1721;
    }

    .green-highlight { color: #56df77; border: round #26683a; }
    .yellow-highlight { color: #f0d047; border: round #6f601b; }
    .orange-highlight { color: #ff813d; border: round #813d1b; }
    .blue-highlight { color: #66c9ff; border: round #24618a; }
    .violet-highlight { color: #d393ff; border: round #65418a; }

    .scroll-result {
        height: 1fr;
        overflow-y: auto;
        padding: 1 2;
        background: #08131f;
    }

    DecoderPanel {
        height: 32;
        min-height: 32;
        margin-bottom: 1;
    }

    #decoder-toolbar {
        height: 4;
        padding: 0 1;
        border-top: solid #142737;
    }

    #decoder-search {
        width: 1fr;
        height: 3;
        margin-right: 1;
        border: round #243a4d;
        background: #08131f;
    }

    .count-label {
        width: 20;
        height: 3;
        padding: 0;
        color: #45c3ff;
        text-align: right;
        content-align: right middle;
    }

    #decoder-list {
        height: 1fr;
        margin: 0 1;
        border: round #1b3040;
        background: #08131f;
        scrollbar-size: 1 1;
        color: #dce3eb;
    }

    #decoder-list > .option-list--option {
        padding: 0 1;
        border-bottom: solid #152736;
    }

    #decoder-list > .option-list--option-highlighted {
        background: #0f2c46;
        color: #ffffff;
        border: round #178bca;
    }

    #decoder-list-footer {
        height: 3;
        margin: 0 1 1 1;
        padding: 0 1;
        border: round #1b3040;
        background: #08131f;
        color: #b6c2ce;
        content-align: left middle;
    }

    DecoderDetailsPanel {
        height: 1fr;
        min-height: 25;
        scrollbar-size: 1 1;
    }

    #decoder-description {
        height: 5;
        min-height: 5;
        padding: 1 2;
        border-top: solid #142737;
        border-bottom: solid #1b3040;
        color: #dce3eb;
    }

    .detail-heading {
        height: 2;
        padding: 0 2;
        color: #35c3ff;
        text-style: bold;
        content-align: left middle;
    }

    .detail-box {
        height: 4;
        padding: 0 2;
        border-bottom: solid #1b3040;
        color: #d7e0e8;
    }

    #decoder-output {
        height: 5;
        min-height: 5;
        padding: 0 2;
        overflow-y: auto;
        border-bottom: solid #1b3040;
        color: #d7e0e8;
    }

    #decoder-status {
        height: 3;
        padding: 0 2;
        color: #72df85;
        content-align: left middle;
        border-bottom: solid #1b3040;
    }

    .actions-heading { margin-top: 1; }

    #decoder-actions {
        height: 4;
        padding: 0 1 1 1;
    }

    #decoder-actions Button {
        width: 1fr;
        min-width: 10;
        height: 3;
        margin-right: 1;
        padding: 0;
        border: round #243a4d;
        background: #091521;
        color: #bdc9d4;
    }

    #decoder-actions Button:last-of-type { margin-right: 0; }
    #run-decoder { color: #55e177; border: round #245d39; }

    #workbench-status-bar {
        height: 2;
        padding: 0 1;
        background: #07111c;
        color: #a7b4c2;
        border: round #1a3040;
    }

    #footer-state { width: 20; height: 1; }
    #footer-working-directory { width: 1fr; height: 1; }
    #footer-mode { width: 16; height: 1; text-align: right; }
    #footer-updates { width: 22; height: 1; text-align: center; }
    #footer-help { width: 20; height: 1; text-align: right; }

    Screen.compact-layout #left-column { width: 24; min-width: 24; }
    Screen.compact-layout #right-column { width: 38; min-width: 38; }
    Screen.compact-layout #header-right { display: none; }
    Screen.compact-layout #workbench-brand { width: 40%; }
    Screen.compact-layout #header-status { width: 60%; }
    Screen.compact-layout .metric-card { min-width: 22; }
    Screen.compact-layout #quick-start { width: 35; }
    Screen.compact-layout #footer-updates { display: none; }
    Screen.compact-layout #footer-help { display: none; }
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
        Binding("question_mark", "show_help", "Help"),
        Binding("q", "quit", "Quit"),
    ]

    def __init__(self):
        super().__init__()
        self.services = WorkbenchServices()
        self.snapshot = AnalysisSnapshot()
        self.selected_decoder = 0
        self.input_mode = "auto"
        session_seed = f"{Path.cwd()}:{id(self)}".encode("utf-8")
        self.session_id = sha256(session_seed).hexdigest()[:8]
        self.session_started = datetime.now()

    def compose(self) -> ComposeResult:
        yield WorkbenchHeader(
            self.services.state,
            version=self.services.engine_version(),
            session_id=self.session_id,
        )
        with Horizontal(id="application-body"):
            with Vertical(id="left-column"):
                yield NavigationPanel()
            with VerticalScroll(id="center-column"):
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
                    session_id=self.session_id,
                    started_at=f"{self.session_started:%H:%M:%S}",
                    snapshot=self.snapshot,
                )
                yield ResultsPanel(self.snapshot, self.services.state)
            with VerticalScroll(id="right-column"):
                yield DecoderPanel(self.services.decoder_rows())
                label, description = self.services.decoder_details(
                    self.selected_decoder
                )
                yield DecoderDetailsPanel(label, description, self.snapshot)
        yield WorkbenchStatusBar(self.services.state)

    def on_resize(self, event: Resize) -> None:
        self.screen.set_class(event.size.width < 145, "compact-layout")

    async def _replace_dynamic_view(self, widget) -> None:
        current = self.query_one("#dynamic-view")
        await current.remove()
        await self.query_one("#center-column").mount(widget)

    async def refresh_results(self, *, reveal: bool = False) -> None:
        self.query_one(StatusCards).refresh_snapshot(self.snapshot)
        await self._replace_dynamic_view(
            ResultsPanel(self.snapshot, self.services.state)
        )
        if reveal:
            self.hide_evidence_input()
            # On short terminals the results panel sits below the fold of the
            # scrollable center column, so a finished analysis looked like a
            # no-op. Bring the fresh panel into view once it has a layout.
            panel = self.query_one("#dynamic-view")
            self.call_after_refresh(panel.scroll_visible, animate=False, top=True)

    async def refresh_decoder_details(self, *, reveal: bool = False) -> None:
        current = self.query_one(DecoderDetailsPanel)
        await current.remove()
        label, description = self.services.decoder_details(self.selected_decoder)
        panel = DecoderDetailsPanel(label, description, self.snapshot)
        await self.query_one("#right-column").mount(panel)
        if reveal:
            self.call_after_refresh(panel.scroll_visible, animate=False, top=True)

    def set_activity(self, message: str | None) -> None:
        """Reflect long-running work in the status bar so clicks aren't silent."""
        footer = self.query_one("#footer-state", Static)
        if message:
            footer.update(f"[#f0ca70]●[/#f0ca70] {markup_escape(message)}")
        else:
            footer.update("[#36d277]●[/#36d277] Ready")

    def reveal_evidence_input(self) -> None:
        panel = self.query_one(InvestigationPanel)
        panel.add_class("input-active")
        self.query_one("#evidence-input", Input).focus()

    def hide_evidence_input(self) -> None:
        self.query_one(InvestigationPanel).remove_class("input-active")

    @staticmethod
    def _normalize_input_path(raw: str, *, posix: bool | None = None) -> str:
        """Normalize paths pasted by terminal file-drop implementations.

        Windows Terminal inserts a dropped path as pasted text. When the app
        runs under WSL that text may still be a Windows path, so translate the
        drive prefix to the conventional WSL mount before resolving it.
        """
        text = raw.strip()
        if len(text) >= 2 and text[0] == text[-1] and text[0] in "'\"":
            text = text[1:-1]

        if text.lower().startswith("file://"):
            parsed = urlparse(text)
            text = unquote(parsed.path)
            if parsed.netloc and parsed.netloc.lower() != "localhost":
                text = f"//{parsed.netloc}{text}"
            # file:///C:/... encodes a Windows drive with a leading slash.
            if re.match(r"^/[A-Za-z]:/", text):
                text = text[1:]

        if posix is None:
            posix = os.name != "nt"
        windows_path = re.match(
            r"^(?P<drive>[A-Za-z]):[\\/](?P<tail>.*)$", text, re.DOTALL
        )
        if posix and windows_path:
            drive = windows_path.group("drive").lower()
            tail = windows_path.group("tail").replace("\\", "/")
            text = f"/mnt/{drive}/{tail}"
        return text

    @classmethod
    def _existing_input_path(cls, raw: str) -> tuple[Path, bool] | None:
        """Resolve real file/folder inputs without rejecting long pasted payloads."""
        candidate = Path(cls._normalize_input_path(raw)).expanduser()
        try:
            if candidate.is_file():
                return candidate, False
            if candidate.is_dir():
                return candidate, True
        except (OSError, ValueError):
            return None
        return None

    def accept_dropped_path(self, raw: str) -> bool:
        """Load and analyze a real path delivered through terminal paste."""
        resolved = self._existing_input_path(raw)
        if resolved is None:
            return False
        path, _is_directory = resolved
        field = self.query_one("#evidence-input", Input)
        field.value = str(path)
        field.focus()
        self.input_mode = "auto"
        self.notify(
            f"Dropped {markup_escape(path.name or str(path))}; starting analysis.",
            severity="information",
        )
        self.start_analysis()
        return True

    def on_paste(self, event: Paste) -> None:
        """Accept a drop even when the evidence field was not focused."""
        if self.accept_dropped_path(event.text):
            event.stop()

    @on(Click, "#drop-zone")
    def drop_zone_clicked(self) -> None:
        """Make the visual drop zone useful for terminals without file drops."""
        self.reveal_evidence_input()
        self.notify(
            "Drop a file into the terminal or paste its path.",
            severity="information",
        )

    def _read_input(self, raw: str | None = None) -> tuple[bytes, str]:
        if raw is None:
            raw = self.query_one("#evidence-input", Input).value
        raw = raw.strip()
        if not raw:
            raise ValueError("Enter text, hex, or a file path first.")
        resolved = self._existing_input_path(raw)
        if resolved is not None:
            path, is_directory = resolved
            if is_directory:
                raise IsADirectoryError(str(path))
            return self.services.read_file(path), path.name
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
        self.call_from_thread(self.set_activity, "Analyzing evidence…")
        try:
            raw = self.call_from_thread(
                lambda: self.query_one("#evidence-input", Input).value.strip()
            )
            resolved = self._existing_input_path(raw) if raw else None
            if resolved is not None and resolved[1]:
                snapshot = self.services.analyze_path(resolved[0])
            else:
                data, source_name = self._read_input(raw)
                snapshot = self.services.analyze(data, source_name)
        except Exception as exc:
            self.call_from_thread(self.notify, markup_escape(exc), severity="error")
            return
        finally:
            self.call_from_thread(self.set_activity, None)
        self.snapshot = snapshot
        # Textual 1.0 types an unused async callback as Awaitable[Never], even
        # though call_from_thread awaits it and returns None at runtime.
        self.call_from_thread(self.refresh_results, reveal=True)  # type: ignore[arg-type]
        self.call_from_thread(self.refresh_decoder_details)  # type: ignore[arg-type]
        message = (
            f"Analysis complete ({snapshot.batch_succeeded}/{snapshot.batch_total} files)"
            if snapshot.batch_total > 1
            else "Analysis complete"
        )
        if snapshot.batch_errors:
            message += f"; {len(snapshot.batch_errors)} failed"
        self.call_from_thread(self.notify, message, severity="information")

    @on(OptionList.OptionSelected, "#decoder-list")
    async def decoder_selected(self, event: OptionList.OptionSelected) -> None:
        self.selected_decoder = int(event.option.id or "0")
        await self.refresh_decoder_details()

    @on(Input.Changed, "#decoder-search")
    def decoder_search_changed(self, event: Input.Changed) -> None:
        needle = event.value.strip().lower()
        option_list = self.query_one("#decoder-list", OptionList)
        option_list.clear_options()
        rows = self.services.decoder_rows()
        for index, label, description in rows:
            if not needle or needle in label.lower() or needle in description.lower():
                option_list.add_option(DecoderPanel.option(index, label))

    @on(Button.Pressed, "#copy-output")
    def copy_output_pressed(self) -> None:
        if self.snapshot.decoded_output is None:
            self.notify("No decoded output to copy.", severity="warning")
            return
        text = self.snapshot.decoded_output.decode("utf-8", errors="replace")
        self.copy_to_clipboard(text)
        self.notify("Decoded output copied.", severity="information")

    @on(Button.Pressed, "#run-decoder")
    def run_decoder_pressed(self) -> None:
        self.start_decoder()

    @work(thread=True, exclusive=True)
    def start_decoder(self) -> None:
        self.call_from_thread(self.set_activity, "Running decoder…")
        try:
            raw = self.call_from_thread(
                lambda: self.query_one("#evidence-input", Input).value.strip()
            )
            data, source_name = self._read_input(raw)
            snapshot = self.services.run_decoder(
                self.selected_decoder, data, source_name
            )
        except Exception as exc:
            self.call_from_thread(self.notify, markup_escape(exc), severity="error")
            return
        finally:
            self.call_from_thread(self.set_activity, None)
        self.snapshot = snapshot
        self.call_from_thread(self.refresh_results)  # type: ignore[arg-type]
        self.call_from_thread(self.refresh_decoder_details, reveal=True)  # type: ignore[arg-type]
        self.call_from_thread(self.notify, "Decoder finished", severity="information")

    @on(Button.Pressed, "#save-output")
    def save_output_pressed(self) -> None:
        if not self.snapshot.decoded_output:
            self.notify("No decoded output to save.", severity="warning")
            return
        digest = sha256(self.snapshot.decoded_output).hexdigest()[:12]
        destination = Path.cwd() / f"titan-decoded-output-{digest}.bin"
        try:
            with destination.open("xb") as handle:
                handle.write(self.snapshot.decoded_output)
        except FileExistsError:
            self.notify(
                f"Output already exists: {markup_escape(destination)}",
                severity="information",
            )
            return
        except OSError as exc:
            self.notify(markup_escape(exc), severity="error")
            return
        self.notify(f"Saved {markup_escape(destination)}", severity="information")

    def paste_mode(self) -> None:
        self.input_mode = "auto"
        self.reveal_evidence_input()

    def hex_mode(self) -> None:
        self.input_mode = "hex"
        self.reveal_evidence_input()
        self.notify("Hex input mode enabled.", severity="information")

    def file_mode(self) -> None:
        self.input_mode = "auto"
        field = self.query_one("#evidence-input", Input)
        field.placeholder = "/path/to/evidence.bin"
        self.reveal_evidence_input()

    async def load_latest_report(self) -> None:
        reports = self.services.reports()
        if not reports:
            self.notify("No reports found.", severity="warning")
            return
        try:
            self.snapshot = self.services.load_report(reports[0])
        except Exception as exc:
            self.notify(markup_escape(exc), severity="error")
            return
        await self.refresh_results(reveal=True)
        await self.refresh_decoder_details()
        self.notify(f"Loaded {markup_escape(reports[0].name)}", severity="information")

    @on(OptionList.OptionSelected, "#quick-start-list")
    async def quick_start_selected(self, event: OptionList.OptionSelected) -> None:
        action = event.option.id or "paste"
        if action == "paste":
            self.paste_mode()
        elif action == "hex":
            self.hex_mode()
        elif action == "file":
            self.file_mode()
        elif action == "report":
            await self.load_latest_report()

    @on(OptionList.OptionSelected, "#navigation-list")
    async def navigation_selected(self, event: OptionList.OptionSelected) -> None:
        route = event.option.id or "dashboard"
        if route == "dashboard":
            await self.action_show_dashboard()
        elif route == "investigation":
            await self.action_focus_evidence()
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
        elif route == "memory":
            await self._show_center_overlay(
                "[b]MEMORY ANALYSIS[/b]\n\nLoad a memory artifact to begin triage."
            )
        elif route == "file-analysis":
            await self.action_focus_evidence()
        elif route == "iocs":
            from .presenters import iocs_text

            await self._show_center_overlay(
                "[b]IOC MANAGER[/b]\n\n" + iocs_text(self.snapshot)
            )
        elif route == "help":
            await self.action_show_help()

    async def action_show_dashboard(self) -> None:
        if not isinstance(self.query_one("#dynamic-view"), ResultsPanel):
            await self.refresh_results()
        self.hide_evidence_input()

    async def action_focus_evidence(self) -> None:
        if not isinstance(self.query_one("#dynamic-view"), ResultsPanel):
            await self.refresh_results()
        self.reveal_evidence_input()

    def action_focus_decoders(self) -> None:
        self.query_one("#decoder-list", OptionList).focus()

    async def action_show_reports(self) -> None:
        reports = self.services.reports()
        lines = ["[b]REPORTS & EVIDENCE[/b]", ""]
        lines.extend(f"• {markup_escape(path.name)}" for path in reports[:50])
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

    async def action_show_help(self) -> None:
        await self._show_center_overlay(
            "[b]HELP & KEYBOARD COMMANDS[/b]\n\n"
            "H  Dashboard          A  Focus evidence input\n"
            "D  Decoder list       R  Reports browser\n"
            "C  Correlation        T  Timeline\n"
            "I  Local analyst      P  Plugins\n"
            "S  Settings           Q  Quit\n\n"
            "Every long list and result view can be scrolled with the mouse wheel, "
            "arrow keys, Page Up, and Page Down. Press Tab to move between controls."
        )

    async def _show_center_overlay(self, text: str) -> None:
        await self._show_center_overlay_widget(
            Static(text, id="dynamic-view", classes="placeholder-view")
        )

    async def _show_center_overlay_widget(self, widget) -> None:
        await self._replace_dynamic_view(widget)

    @on(Button.Pressed, "#ask-analyst")
    def ask_analyst_pressed(self) -> None:
        question = self.query_one("#analyst-question", Input).value.strip()
        if not question:
            self.notify("Enter a question.", severity="warning")
            return
        try:
            response = self.services.analyst_answer(self.snapshot, question)
        except Exception as exc:
            self.notify(markup_escape(exc), severity="error")
            return
        answer = markup_escape(response.get("answer", ""))
        meta = (
            f"\n\nbackend={markup_escape(response.get('backend'))} "
            f"· intent={markup_escape(response.get('intent'))} "
            f"· fallback={markup_escape(response.get('fallback_used'))}"
        )
        self.query_one("#analyst-answer", Static).update(answer + meta)

    @on(Select.Changed, "#profile-select")
    def profile_changed(self, event: Select.Changed) -> None:
        if event.value:
            self.services.update_state(profile=str(event.value))
            self.refresh_shell_status()
            self.notify(f"Profile: {event.value}", severity="information")

    @on(Switch.Changed, "#offline-switch")
    def offline_changed(self, event: Switch.Changed) -> None:
        self.services.update_state(offline=event.value)
        self.refresh_shell_status()

    @on(Switch.Changed, "#aggressive-switch")
    def aggressive_changed(self, event: Switch.Changed) -> None:
        self.services.update_state(aggressive=event.value)
        self.refresh_shell_status()

    def refresh_shell_status(self) -> None:
        state = self.services.state
        self.query_one(WorkbenchHeader).refresh_state(state)
        self.query_one(WorkbenchStatusBar).refresh_state(state)
        self.query_one(StatusCards).refresh_state(state)

    @on(Button.Pressed, "#window-close")
    def window_close_pressed(self) -> None:
        self.exit()

    @on(Button.Pressed, "#window-minimize, #window-maximize")
    def window_chrome_pressed(self) -> None:
        self.notify(
            "Window sizing is controlled by the terminal host.",
            severity="information",
        )


def main() -> int:
    TitanWorkbenchApp().run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
