"""Enhanced interactive console (the ``titan`` command).

A dashboard-style upgrade of :class:`titan_decoder.interactive.InteractiveApp`
— still stdlib-only, still a pure presentation layer over the existing
engine, decoders, Plugin SDK, and correlation database. All engine behavior
(profiles, offline guard, aggressive auto-detect) is inherited from the base
app; this class only changes what the session looks like and adds read-only
views (plugin manager, reports browser).
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import time
from typing import Any

from .. import __version__ as TITAN_VERSION
from ..interactive import (
    InteractiveApp,
    _QuitSignal,
    format_decode_result,
    format_engine_summary,
)
from .widgets import box, progress_bar, terminal_width, two_column


class EnhancedInteractiveApp(InteractiveApp):
    """Dashboard-style interactive console over the standard app."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.reports_dir = Path.home() / ".titan_decoder" / "reports"
        # Plugin *status* is a read-only count for the dashboard. Computing it
        # loads (executes) plugin modules, so it is cached per session and
        # refreshed only by the plugin manager view.
        self._plugin_status_cache: "tuple[int, int] | None" = None

    # -- plugin discovery -----------------------------------------------------

    def _plugin_manager(self):
        """A PluginManager over the same directory set the engine searches."""
        from ..plugins import PluginManager

        manager = PluginManager()
        for plugin_dir in self.config.get("plugin_dirs", []) or []:
            manager.add_plugin_dir(Path(plugin_dir))
        manager.add_plugin_dir(Path.home() / ".titan_decoder" / "plugins")
        manager.add_plugin_dir(Path(__file__).resolve().parents[1] / "plugins")
        manager.load_plugins()
        return manager

    def _plugin_status(self) -> "tuple[int, int]":
        """(plugin_count, error_count), cached for the dashboard."""
        if self._plugin_status_cache is None:
            try:
                manager = self._plugin_manager()
                count = len(manager.manifest_plugins) + len(manager.loaded_plugins)
                self._plugin_status_cache = (count, len(manager.errors))
            except Exception:
                self._plugin_status_cache = (0, 1)
        return self._plugin_status_cache

    # -- banner / dashboard ----------------------------------------------------

    def _banner(self) -> None:
        width = terminal_width()
        self._print()
        self._print(self.st.cyan(self.st.bold("  TITAN // FORENSIC INTELLIGENCE CONSOLE")))
        self._print(self.st.dim(f"  deterministic analysis · v{TITAN_VERSION} · terminal workspace"))
        self._print("  " + "═" * max(10, width - 4))

    def _dashboard(self) -> None:
        width = terminal_width() - 4
        plugins, errors = self._plugin_status()
        session = [
            f"Engine      v{TITAN_VERSION}",
            f"Profile     {self.profile}",
            f"Network     {'offline' if self.offline else 'online'}",
            f"Aggressive  {'on' if self.aggressive else 'off'}",
        ]
        correlation = Path.home() / ".titan_decoder" / "correlation.sqlite3"
        system = [
            f"Decoders     {len(self.registry)}",
            f"Plugins      {plugins}" + (f" ({errors} errors)" if errors else ""),
            f"Correlation  {'ready' if correlation.exists() else 'not initialized'}",
            f"Reports dir  {self.reports_dir}",
        ]
        rendered = two_column("SESSION", session, "SYSTEM", system, width)
        self._print("  " + rendered.replace("\n", "\n  "))

    def _menu(self) -> str:
        self._print()
        self._dashboard()
        self._print()
        self._print(self.st.bold("  QUICK ACTIONS"))
        self._print(f"    [1] {self.st.green('Analyze input')}          full recursive engine")
        self._print("    [2] Decode with one decoder")
        self._print("    [3] Decoder catalog")
        self._print("    [4] Plugin manager")
        self._print("    [5] Reports browser")
        self._print("    [6] Settings")
        self._print("    [q] Quit")
        return self._ask(self.st.cyan("  titan> ")).strip().lower()

    def _activity(self, label: str) -> None:
        self._print(self.st.dim(f"  {progress_bar(1, 3)} {label}"))

    # -- analysis ---------------------------------------------------------------

    def _summary_box(self, report: "dict[str, Any]") -> str:
        nodes = report.get("nodes") or []
        iocs = report.get("iocs") or {}
        detections = report.get("detections") or []
        relationships = (report.get("correlation") or {}).get("relationships") or []
        return box(
            "ANALYSIS SUMMARY",
            [
                f"Nodes             {len(nodes)}",
                f"IOC count         {sum(len(v) for v in iocs.values() if isinstance(v, list))}",
                f"Detections        {len(detections)}",
                f"Correlation hits  {len(relationships)}",
                f"Maximum depth     {max((int(n.get('depth', 0) or 0) for n in nodes), default=0)}",
            ],
            terminal_width() - 4,
        )

    def action_auto_detect(self) -> None:
        payload = self._read_payload()
        if payload is None:
            return
        data, _ = payload
        self._print()
        mode = " [aggressive]" if self.aggressive else ""
        self._activity(f"Running recursive decoders and analyzers{mode}")
        started = time.monotonic()
        try:
            if self.offline:
                from ..core.offline_guard import block_network

                with block_network():
                    report = self._configured_engine().run_analysis(data)
            else:
                report = self._configured_engine().run_analysis(data)
        except Exception as exc:  # keep the UI alive on engine errors
            self._print(self.st.red(f"  Analysis failed: {exc}"))
            return
        self._print()
        self._print("  " + self._summary_box(report).replace("\n", "\n  "))
        self._print(self.st.dim(f"  Completed in {time.monotonic() - started:.2f}s"))
        self._print()
        self._print(format_engine_summary(self.st, report))
        self._print()
        self._save_report(report)

    def _save_report(self, report: "dict[str, Any]") -> None:
        default = self.reports_dir / "latest.json"
        answer = self._ask(
            f"  Save JSON report [{default}] (Enter=default, -=skip): "
        ).strip().strip("'\"")
        if answer == "-":
            return
        path = Path(os.path.expanduser(answer)) if answer else default
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(report, indent=2), encoding="utf-8")
            self._print(self.st.green(f"  Saved report → {path}"))
        except OSError as exc:
            self._print(self.st.red(f"  Could not save report: {exc}"))

    # -- decoder catalog ---------------------------------------------------------

    def action_pick_decoder(self) -> None:
        self._print()
        self._print(self.st.bold("  DECODER CATALOG"))
        for index, choice in enumerate(self.registry, 1):
            self._print(f"    [{index:>2}] {choice.label:<20} {self.st.dim(choice.description)}")
        self._print("    [b] Back")
        sel = self._ask(self.st.cyan("  decoder> ")).strip().lower()
        if sel in {"", "b", "back"}:
            return
        if not sel.isdigit() or not 1 <= int(sel) <= len(self.registry):
            self._print(self.st.red("  Invalid selection."))
            return
        choice = self.registry[int(sel) - 1]
        payload = self._read_payload()
        if payload is None:
            return
        data, source_len = payload
        self._activity(f"Running {choice.label}")
        try:
            decoded, success = choice.factory().decode(data)
        except Exception as exc:
            self._print(self.st.red(f"  Decoder raised an error: {exc}"))
            return
        self._print()
        self._print(format_decode_result(self.st, choice.label, source_len, decoded, success))
        if success and decoded:
            self._print()
            self._maybe_save(decoded, "Save decoded output to")

    # -- plugin manager -----------------------------------------------------------

    def action_plugins(self) -> None:
        self._print()
        try:
            manager = self._plugin_manager()
        except Exception as exc:
            self._print(self.st.red(f"  Plugin discovery failed: {exc}"))
            return
        count = len(manager.manifest_plugins) + len(manager.loaded_plugins)
        self._plugin_status_cache = (count, len(manager.errors))
        search = ", ".join(str(p) for p in manager.plugin_dirs)
        self._print(
            "  "
            + box(
                "PLUGIN MANAGER",
                [
                    f"Search path  {search}",
                    f"Loaded       {count}",
                    f"Errors       {len(manager.errors)}",
                ],
                terminal_width() - 4,
            ).replace("\n", "\n  ")
        )
        for plugin_id, loaded in sorted(manager.manifest_plugins.items()):
            capabilities = ", ".join(loaded.manifest.capabilities)
            self._print(
                f"    {self.st.green('✓')} {plugin_id:<28} "
                f"v{loaded.manifest.version:<10} {capabilities}"
            )
        for name in sorted(manager.loaded_plugins):
            self._print(f"    {self.st.green('✓')} {name:<28} {self.st.dim('single-file plugin')}")
        for error in manager.errors:
            self._print(f"    {self.st.red('✗')} {error['path']}: {error['error']}")

    # -- reports browser ------------------------------------------------------------

    def action_reports(self) -> None:
        self._print()
        self._print(self.st.bold("  REPORTS BROWSER"))
        if not self.reports_dir.exists():
            self._print(self.st.dim("  No reports directory exists yet."))
            return
        reports = sorted(
            self.reports_dir.glob("*.json"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )[:20]
        if not reports:
            self._print(self.st.dim("  No JSON reports found."))
            return
        for index, path in enumerate(reports, 1):
            self._print(f"    [{index}] {path.name}")
        self._print("    [b] Back")
        sel = self._ask(self.st.cyan("  report> ")).strip().lower()
        if sel in {"", "b", "back"}:
            return
        if not sel.isdigit() or not 1 <= int(sel) <= len(reports):
            self._print(self.st.red("  Invalid report selection."))
            return
        try:
            report = json.loads(reports[int(sel) - 1].read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            self._print(self.st.red(f"  Could not open report: {exc}"))
            return
        self._print()
        self._print("  " + self._summary_box(report).replace("\n", "\n  "))
        self._print()
        self._print(format_engine_summary(self.st, report))

    # -- settings ----------------------------------------------------------------------

    def action_options(self) -> None:
        while True:
            self._print()
            self._print(
                "  "
                + box(
                    "SETTINGS",
                    [
                        f"[1] Analysis profile      {self.profile}",
                        f"[2] Network mode          {'offline' if self.offline else 'online'}",
                        f"[3] Aggressive detection  {'on' if self.aggressive else 'off'}",
                        f"[4] Reports directory     {self.reports_dir}",
                        "[b] Back",
                    ],
                    terminal_width() - 4,
                ).replace("\n", "\n  ")
            )
            sel = self._ask(self.st.cyan("  settings> ")).strip().lower()
            if sel in {"", "b", "back"}:
                return
            if sel == "1":
                value = self._ask("  Profile (safe/fast/full): ").strip().lower()
                if value in {"safe", "fast", "full"}:
                    self.profile = value
                else:
                    self._print(self.st.red("  Unknown profile."))
            elif sel == "2":
                value = self._ask("  Network (offline/online): ").strip().lower()
                if value in {"offline", "off"}:
                    self.offline = True
                elif value in {"online", "on"}:
                    self.offline = False
                else:
                    self._print(self.st.red("  Unknown network mode."))
            elif sel == "3":
                # Simple toggle, same semantics as the base app: aggressive
                # only affects auto-detect and is fully session-scoped.
                self.aggressive = not self.aggressive
                state = "on" if self.aggressive else "off"
                self._print(self.st.green(f"  Aggressive auto-detect is now {state}."))
                if self.aggressive:
                    self._print(
                        self.st.dim(
                            "  Heads-up: expect more (and weaker) results — good for "
                            "hands-on testing, noisier for real triage."
                        )
                    )
            elif sel == "4":
                value = self._ask("  Reports directory: ").strip()
                if value:
                    self.reports_dir = Path(os.path.expanduser(value))
            else:
                self._print(self.st.red("  Unknown setting."))

    # -- main loop -----------------------------------------------------------------------

    def run(self) -> int:
        self._banner()
        try:
            while True:
                choice = self._menu()
                if choice in {"q", "quit", "exit"}:
                    break
                if choice == "1":
                    self.action_auto_detect()
                elif choice == "2":
                    self.action_pick_decoder()
                elif choice == "3":
                    self.action_list_decoders()
                elif choice == "4":
                    self.action_plugins()
                elif choice == "5":
                    self.action_reports()
                elif choice == "6":
                    self.action_options()
                elif choice:
                    self._print(self.st.red("  Unknown option — choose 1 through 6, or q."))
        except (_QuitSignal, KeyboardInterrupt):
            self._print()
        self._print(self.st.dim("  Session closed."))
        return 0
