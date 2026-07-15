"""The Analyst Workbench: a terminal application for exploring Titan reports.

Launched as ``titan-workbench`` (or ``python -m titan_decoder.workbench.app``).
Stdlib-only and line-based, like the rest of Titan's interfaces, so it works
locally, over SSH, and in Codespaces. It is strictly read-only over reports:
exploration, search, annotation, and export — never re-analysis.

Interface decision: the workbench is a terminal application rather than a
local web or desktop app. That keeps it inside Titan's offline-first,
dependency-light guarantees (no server, no browser stack, nothing listening
on a socket in an evidentiary environment) and reuses the injectable-I/O
testing model the interactive console established.
"""

from __future__ import annotations

import os
from pathlib import Path
import sys
from typing import Callable, Optional

from ..interactive import Style, _color_enabled
from .export import (
    GRAPH_FORMATS,
    export_case_bundle,
    export_graph,
    export_iocs_csv,
    export_timeline_csv,
)
from .models import TitanReport
from .render import (
    correlation_view,
    decode_tree,
    detection_view,
    evidence_view,
    indicator_view,
    node_detail,
    report_overview,
    timeline_view,
)
from .search import search_reports
from .workspace import CASE_STATUSES, InvestigationWorkspace


class AnalystWorkbench:
    """The menu loop. I/O is injectable so the whole thing is testable."""

    def __init__(
        self,
        input_fn: Callable[[str], str] = input,
        out=None,
        style: Optional[Style] = None,
    ):
        self.input_fn = input_fn
        self.out = out or sys.stdout
        self.st = style if style is not None else Style(_color_enabled(self.out))
        self.workspace = InvestigationWorkspace("Titan Investigation")
        self.workspace_path: "Path | None" = None
        self.reports: list[TitanReport] = []
        self.active_index: "int | None" = None

    # -- low-level I/O ---------------------------------------------------------

    def _print(self, *parts: str) -> None:
        print(*parts, file=self.out)

    def _ask(self, prompt: str) -> str:
        return self.input_fn(prompt)

    def _block(self, text: str) -> None:
        self._print()
        self._print("  " + text.replace("\n", "\n  "))

    @property
    def active(self) -> "TitanReport | None":
        if self.active_index is None or not 0 <= self.active_index < len(self.reports):
            return None
        return self.reports[self.active_index]

    # -- banner / menu ------------------------------------------------------------

    def _banner(self) -> None:
        self._print()
        self._print(self.st.cyan(self.st.bold("  TITAN // ANALYST WORKBENCH")))
        self._print(
            self.st.dim("  reports · timelines · decode trees · indicators · investigations")
        )
        self._print("  " + "═" * 72)

    def _status(self) -> None:
        self._print()
        self._print(f"  Workspace : {self.workspace.name}")
        self._print(f"  Reports   : {len(self.reports)}")
        self._print(f"  Active    : {self.active.path.name if self.active else 'none'}")
        self._print(f"  Notes     : {len(self.workspace.notes)}")

    def _menu(self) -> str:
        self._status()
        self._print()
        self._print("    [1] Add report or report directory")
        self._print("    [2] Select active report")
        self._print("    [3] Report overview")
        self._print("    [4] Decode-tree explorer")
        self._print("    [5] Graph viewer")
        self._print("    [6] IOC browser")
        self._print("    [7] Detection browser")
        self._print("    [8] Timeline explorer")
        self._print("    [9] Evidence browser")
        self._print("    [c] Correlation view")
        self._print("    [/] Search all loaded reports")
        self._print("    [n] Investigation notes and tags")
        self._print("    [e] Export")
        self._print("    [s] Save workspace")
        self._print("    [o] Open workspace")
        self._print("    [q] Quit")
        return self._ask(self.st.cyan("  workbench> ")).strip().lower()

    # -- report library --------------------------------------------------------------

    def add_path(self, path_text: str) -> None:
        path = Path(os.path.expanduser(path_text.strip().strip("'\"")))
        candidates = sorted(path.glob("*.json")) if path.is_dir() else [path]
        loaded = 0
        existing = {str(r.path.resolve()) for r in self.reports}
        for candidate in candidates:
            try:
                resolved = str(candidate.resolve())
                if resolved in existing:
                    continue
                report = TitanReport.load(candidate)
                self.reports.append(report)
                existing.add(resolved)
                self.workspace.add_report(candidate)
                loaded += 1
            except (OSError, ValueError) as exc:
                self._print(self.st.red(f"  Skipped {candidate}: {exc}"))
        self.reports.sort(key=lambda r: str(r.path))
        if self.reports and self.active_index is None:
            self.active_index = 0
        self._print(f"  Loaded {loaded} report(s).")

    def select_report(self) -> None:
        if not self.reports:
            self._print("  No reports loaded.")
            return
        for index, report in enumerate(self.reports, 1):
            s = report.summary
            marker = "▸" if index - 1 == self.active_index else " "
            self._print(
                f"   {marker}[{index}] {report.path.name:<34} "
                f"{s.risk_level:<8} {s.ioc_count} IOCs, {s.detection_count} detections"
            )
        choice = self._ask(self.st.cyan("  select> ")).strip()
        if choice.isdigit() and 1 <= int(choice) <= len(self.reports):
            self.active_index = int(choice) - 1

    def require_active(self) -> "TitanReport | None":
        if not self.active:
            self._print("  Select or load a report first.")
            return None
        return self.active

    # -- views --------------------------------------------------------------------------

    def show_filtered(self, renderer) -> None:
        report = self.require_active()
        if not report:
            return
        query = self._ask("  Filter (Enter for all): ").strip()
        self._block(renderer(report, filter_text=query))

    def graph_viewer(self) -> None:
        """Interactive decode-graph navigation: tree, node drill-down, export."""

        report = self.require_active()
        if not report:
            return
        self._block(decode_tree(report))
        while True:
            self._print()
            self._print(self.st.dim("  Enter a node id for detail, [x] export graph, [b] back"))
            choice = self._ask(self.st.cyan("  graph> ")).strip().lower()
            if choice in {"", "b", "back"}:
                return
            if choice == "x":
                fmt = self._ask(f"  Format {GRAPH_FORMATS}: ").strip().lower() or "mermaid"
                if fmt not in GRAPH_FORMATS:
                    self._print(self.st.red("  Unknown graph format."))
                    continue
                path_text = self._ask("  Output path: ").strip()
                if not path_text:
                    continue
                try:
                    export_graph(report, Path(os.path.expanduser(path_text)), fmt)
                    self._print(self.st.green(f"  Exported {fmt} graph → {path_text}"))
                except (OSError, ValueError) as exc:
                    self._print(self.st.red(f"  Graph export failed: {exc}"))
                continue
            self._block(node_detail(report, choice))

    def global_search(self) -> None:
        if not self.reports:
            self._print("  No reports loaded.")
            return
        query = self._ask("  Search query: ").strip()
        hits = search_reports(self.reports, query)
        self._print(f"  {len(hits)} hit(s)")
        for hit in hits[:50]:
            self._print(f"    {Path(hit.report_path).name} {hit.location} :: {hit.preview}")

    # -- annotations ---------------------------------------------------------------------

    def notes(self) -> None:
        report = self.require_active()
        if not report:
            return
        entry = self.workspace.add_report(report.path)
        self._print(f"  Tags   : {', '.join(entry.tags) or 'none'}")
        self._print(f"  Note   : {entry.note or 'none'}")
        self._print(f"  Status : {entry.status}")
        self._print("    [1] Add tag")
        self._print("    [2] Set report note")
        self._print("    [3] Add workspace note")
        self._print("    [4] Set case status")
        choice = self._ask(self.st.cyan("  notes> ")).strip()
        if choice == "1":
            self.workspace.tag(report.path, self._ask("  Tag: "))
        elif choice == "2":
            self.workspace.set_note(report.path, self._ask("  Note: "))
        elif choice == "3":
            note = self._ask("  Workspace note: ").strip()
            if note:
                self.workspace.notes.append(note)
        elif choice == "4":
            status = self._ask(f"  Status {CASE_STATUSES}: ").strip().lower()
            try:
                self.workspace.set_status(report.path, status)
            except ValueError as exc:
                self._print(self.st.red(f"  {exc}"))

    # -- exports -------------------------------------------------------------------------

    def export_menu(self) -> None:
        if not self.reports:
            self._print("  No reports loaded.")
            return
        self._print("    [1] IOC CSV (all loaded reports)")
        self._print("    [2] Timeline CSV (all loaded reports)")
        self._print("    [3] Investigation ZIP bundle")
        self._print("    [4] Active report graph (json/dot/mermaid)")
        choice = self._ask(self.st.cyan("  export> ")).strip()
        if choice == "4":
            self.graph_export_prompt()
            return
        path_text = self._ask("  Output path: ").strip()
        if not path_text:
            return
        path = Path(os.path.expanduser(path_text))
        try:
            if choice == "1":
                export_iocs_csv(self.reports, path)
            elif choice == "2":
                export_timeline_csv(self.reports, path)
            elif choice == "3":
                export_case_bundle(self.workspace, self.reports, path)
            else:
                self._print(self.st.red("  Unknown export."))
                return
        except OSError as exc:
            self._print(self.st.red(f"  Export failed: {exc}"))
            return
        self._print(self.st.green(f"  Exported → {path}"))

    def graph_export_prompt(self) -> None:
        report = self.require_active()
        if not report:
            return
        fmt = self._ask(f"  Format {GRAPH_FORMATS}: ").strip().lower() or "mermaid"
        if fmt not in GRAPH_FORMATS:
            self._print(self.st.red("  Unknown graph format."))
            return
        path_text = self._ask("  Output path: ").strip()
        if not path_text:
            return
        try:
            export_graph(report, Path(os.path.expanduser(path_text)), fmt)
            self._print(self.st.green(f"  Exported {fmt} graph → {path_text}"))
        except (OSError, ValueError) as exc:
            self._print(self.st.red(f"  Graph export failed: {exc}"))

    # -- workspace persistence --------------------------------------------------------------

    def save_workspace(self) -> None:
        default = self.workspace_path or Path.cwd() / "titan-workspace.json"
        answer = self._ask(f"  Workspace path [{default}]: ").strip()
        path = Path(os.path.expanduser(answer)) if answer else default
        try:
            self.workspace.save(path)
        except OSError as exc:
            self._print(self.st.red(f"  Could not save workspace: {exc}"))
            return
        self.workspace_path = path
        self._print(self.st.green(f"  Saved workspace → {path}"))

    def open_workspace(self) -> None:
        answer = self._ask("  Workspace path: ").strip()
        if not answer:
            return
        path = Path(os.path.expanduser(answer))
        try:
            workspace = InvestigationWorkspace.load(path)
        except (OSError, ValueError) as exc:
            self._print(self.st.red(f"  Could not open workspace: {exc}"))
            return
        self.workspace = workspace
        self.workspace_path = path
        self.reports = []
        for entry in self.workspace.entries:
            try:
                self.reports.append(TitanReport.load(entry.report_path))
            except (OSError, ValueError) as exc:
                self._print(self.st.yellow(f"  Missing report {entry.report_path}: {exc}"))
        self.active_index = 0 if self.reports else None
        self._print(
            f"  Opened {self.workspace.name} with {len(self.reports)} available report(s)."
        )

    # -- main loop ------------------------------------------------------------------------------

    def run(self) -> int:
        self._banner()
        try:
            while True:
                choice = self._menu()
                if choice in {"q", "quit", "exit"}:
                    break
                if choice == "1":
                    self.add_path(self._ask("  Report file or directory: "))
                elif choice == "2":
                    self.select_report()
                elif choice == "3":
                    report = self.require_active()
                    if report:
                        self._block(report_overview(report))
                elif choice == "4":
                    self.show_filtered(decode_tree)
                elif choice == "5":
                    self.graph_viewer()
                elif choice == "6":
                    self.show_filtered(indicator_view)
                elif choice == "7":
                    self.show_filtered(detection_view)
                elif choice == "8":
                    self.show_filtered(timeline_view)
                elif choice == "9":
                    self.show_filtered(evidence_view)
                elif choice == "c":
                    report = self.require_active()
                    if report:
                        self._block(correlation_view(report))
                elif choice == "/":
                    self.global_search()
                elif choice == "n":
                    self.notes()
                elif choice == "e":
                    self.export_menu()
                elif choice == "s":
                    self.save_workspace()
                elif choice == "o":
                    self.open_workspace()
                elif choice:
                    self._print(self.st.red("  Unknown option."))
        except (EOFError, KeyboardInterrupt):
            self._print()
        self._print(self.st.dim("  Workbench closed."))
        return 0


def main(argv=None) -> int:
    """Console entry point for the ``titan-workbench`` command."""

    return AnalystWorkbench().run()


if __name__ == "__main__":
    raise SystemExit(main())
