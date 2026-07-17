from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class WorkbenchState:
    profile: str = "fast"
    offline: bool = True
    aggressive: bool = False
    reports_dir: Path = Path.home() / ".titan_decoder" / "reports"


@dataclass
class AnalysisSnapshot:
    source_name: str = "No investigation loaded"
    source_size: int = 0
    duration_seconds: float = 0.0
    report: dict[str, Any] = field(default_factory=dict)
    decoded_output: bytes | None = None
    decoder_label: str | None = None
    decoder_success: bool | None = None
    batch_total: int = 1
    batch_succeeded: int = 1
    batch_errors: tuple[str, ...] = ()

    @property
    def nodes(self) -> list[dict[str, Any]]:
        values = self.report.get("nodes")
        if not isinstance(values, list):
            return []
        return [item for item in values if isinstance(item, dict)]

    @property
    def iocs(self) -> dict[str, list[Any]]:
        values = self.report.get("iocs")
        if not isinstance(values, dict):
            return {}
        return {
            str(kind): list(items)
            for kind, items in values.items()
            if isinstance(items, list)
        }

    @property
    def detections(self) -> list[dict[str, Any]]:
        values = self.report.get("detections")
        if not isinstance(values, list):
            return []
        return [item for item in values if isinstance(item, dict)]

    @property
    def strings(self) -> list[str]:
        values = (
            self.report.get("interesting_strings") or self.report.get("strings") or []
        )
        if not isinstance(values, list):
            return []
        return [str(value) for value in values]

    @property
    def timeline(self) -> list[dict[str, Any]]:
        evidence = self.report.get("evidence") or {}
        source = (
            (evidence.get("events") if isinstance(evidence, dict) else None)
            or self.report.get("timeline")
            or self.report.get("evidence_timeline")
            or []
        )
        if not isinstance(source, list):
            return []
        return [item for item in source if isinstance(item, dict)]

    @property
    def relationships(self) -> list[dict[str, Any]]:
        correlation = self.report.get("correlation") or {}
        if not isinstance(correlation, dict):
            return []
        values = correlation.get("relationships")
        if not isinstance(values, list):
            return []
        return [item for item in values if isinstance(item, dict)]

    @property
    def ioc_count(self) -> int:
        return sum(
            len(values) for values in self.iocs.values() if isinstance(values, list)
        )
