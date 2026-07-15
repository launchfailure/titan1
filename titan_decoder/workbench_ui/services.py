from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any
import json
import os
import resource
import time

from titan_decoder import __version__ as TITAN_VERSION
from titan_decoder.config import Config
from titan_decoder.core.engine import TitanEngine
from titan_decoder.interactive import build_decoder_registry

from .models import AnalysisSnapshot, WorkbenchState


class WorkbenchServices:
    """Adapter from the terminal workbench to Titan's existing engine."""

    _AGGRESSIVE_DECODERS = ("base32", "uuencode", "quoted_printable", "asn1")

    def __init__(self, config: Config | None = None):
        self.config = config or Config()
        self.state = WorkbenchState()
        self.registry = build_decoder_registry()
        self._baseline_decoders = dict(self.config.get("decoders", {}) or {})
        self._baseline_min_score = self.config.get("min_score_threshold", 0.01)

    def update_state(self, **changes: Any) -> WorkbenchState:
        self.state = replace(self.state, **changes)
        return self.state

    def engine_version(self) -> str:
        return TITAN_VERSION

    def decoder_count(self) -> int:
        return len(self.registry)

    def decoder_rows(self) -> list[tuple[int, str, str]]:
        return [
            (index, choice.label, choice.description)
            for index, choice in enumerate(self.registry)
        ]

    def decoder_details(self, index: int) -> tuple[str, str]:
        choice = self.registry[index]
        return choice.label, choice.description

    def _configured_engine(self) -> TitanEngine:
        cfg = self.config
        if self.state.profile in {"safe", "fast"}:
            cfg.set("max_recursion_depth", 3)
            cfg.set("max_node_count", 50)
        elif self.state.profile == "full":
            cfg.set("max_recursion_depth", 8)
            cfg.set("max_node_count", 200)

        decoders = dict(self._baseline_decoders)
        if self.state.aggressive:
            for name in self._AGGRESSIVE_DECODERS:
                decoders[name] = True
            cfg.set("min_score_threshold", 0.0)
            cfg.set("max_recursion_depth", max(int(cfg.get("max_recursion_depth", 5)), 6))
            cfg.set("max_node_count", max(int(cfg.get("max_node_count", 100)), 200))
        else:
            cfg.set("min_score_threshold", self._baseline_min_score)
        cfg.set("decoders", decoders)
        return TitanEngine(cfg)

    def analyze(self, data: bytes, source_name: str) -> AnalysisSnapshot:
        started = time.monotonic()
        engine = self._configured_engine()
        if self.state.offline:
            from titan_decoder.core.offline_guard import block_network
            with block_network():
                report = engine.run_analysis(data)
        else:
            report = engine.run_analysis(data)
        return AnalysisSnapshot(
            source_name=source_name,
            source_size=len(data),
            duration_seconds=time.monotonic() - started,
            report=report,
        )


    def analyze_path(self, path: Path) -> AnalysisSnapshot:
        """Analyze one file or a directory queue, saving one report per file.

        Directory processing is deterministic (sorted paths), skips directories,
        and records non-fatal failures in the returned snapshot.
        """
        path = path.expanduser()
        candidates = [path] if path.is_file() else sorted(p for p in path.rglob("*") if p.is_file())
        if not candidates:
            raise ValueError(f"No files found at {path}")
        latest: AnalysisSnapshot | None = None
        errors: list[str] = []
        succeeded = 0
        for candidate in candidates:
            try:
                latest = self.analyze(candidate.read_bytes(), candidate.name)
                safe_name = candidate.name.replace("/", "_") + ".json"
                self.save_report(latest, self.state.reports_dir / safe_name)
                succeeded += 1
            except Exception as exc:
                errors.append(f"{candidate}: {exc}")
        if latest is None:
            raise RuntimeError("Every queued file failed analysis: " + "; ".join(errors[:5]))
        latest.batch_total = len(candidates)
        latest.batch_succeeded = succeeded
        latest.batch_errors = tuple(errors)
        return latest

    def analyst_answer(self, snapshot: AnalysisSnapshot, question: str) -> dict[str, Any]:
        if not snapshot.report:
            raise ValueError("Load or analyze a Titan report before asking the analyst.")
        from titan_decoder.analyst.engine import AnalystEngine
        return AnalystEngine([snapshot.report]).ask(question).to_dict()

    def run_decoder(self, index: int, data: bytes, source_name: str) -> AnalysisSnapshot:
        started = time.monotonic()
        choice = self.registry[index]
        decoded, success = choice.factory().decode(data)
        return AnalysisSnapshot(
            source_name=source_name,
            source_size=len(data),
            duration_seconds=time.monotonic() - started,
            decoded_output=decoded,
            decoder_label=choice.label,
            decoder_success=bool(success),
        )

    def reports(self) -> list[Path]:
        directory = self.state.reports_dir
        if not directory.exists():
            return []
        return sorted(
            directory.glob("*.json"),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )

    def report_count(self, directory: Path | None = None) -> int:
        """Return the number of JSON reports in a directory.

        When no directory is supplied, use the configured reports directory.
        Missing or non-directory paths safely return zero.
        """
        target = directory or self.state.reports_dir
        if not target.is_dir():
            return 0
        return sum(1 for path in target.glob("*.json") if path.is_file())

    def save_report(self, snapshot: AnalysisSnapshot, destination: Path | None = None) -> Path:
        path = destination or self.state.reports_dir / "latest.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(snapshot.report, indent=2), encoding="utf-8")
        return path

    def load_report(self, path: Path) -> AnalysisSnapshot:
        report = json.loads(path.read_text(encoding="utf-8"))
        return AnalysisSnapshot(
            source_name=path.name,
            source_size=path.stat().st_size,
            report=report,
        )

    def plugin_status(self) -> tuple[int, int]:
        try:
            from titan_decoder.plugins import PluginManager
            manager = PluginManager()
            for plugin_dir in self.config.get("plugin_dirs", []) or []:
                manager.add_plugin_dir(Path(plugin_dir))
            manager.add_plugin_dir(Path.home() / ".titan_decoder" / "plugins")
            manager.add_plugin_dir(Path(__file__).resolve().parents[1] / "plugins")
            manager.load_plugins()
            count = len(manager.manifest_plugins) + len(manager.loaded_plugins)
            return count, len(manager.errors)
        except Exception:
            return 0, 1

    def correlation_status(self) -> str:
        path = Path.home() / ".titan_decoder" / "correlation.sqlite3"
        return "ready" if path.exists() else "not initialized"

    def system_metrics(self) -> dict[str, str]:
        cpu = "n/a"
        memory = "n/a"
        try:
            load = os.getloadavg()[0]
            cpu = f"{load:.2f} load"
        except (AttributeError, OSError):
            pass
        try:
            usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            memory_mb = usage / 1024
            memory = f"{memory_mb:.0f} MB"
        except Exception:
            pass
        return {
            "cpu": cpu,
            "memory": memory,
            "workers": "1",
            "disk": "local",
        }
