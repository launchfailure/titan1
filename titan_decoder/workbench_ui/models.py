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
        return list(self.report.get("nodes") or [])

    @property
    def iocs(self) -> dict[str, list[Any]]:
        return dict(self.report.get("iocs") or {})

    @property
    def detections(self) -> list[dict[str, Any]]:
        return list(self.report.get("detections") or [])

    @property
    def strings(self) -> list[str]:
        values = self.report.get("interesting_strings") or self.report.get("strings") or []
        return [str(value) for value in values]

    @property
    def timeline(self) -> list[dict[str, Any]]:
        evidence = self.report.get("evidence") or {}
        source = (evidence.get("events") if isinstance(evidence, dict) else None) or self.report.get("timeline") or self.report.get("evidence_timeline") or []
        return [item for item in source if isinstance(item, dict)]

    @property
    def relationships(self) -> list[dict[str, Any]]:
        correlation = self.report.get("correlation") or {}
        return list(correlation.get("relationships") or [])

    @property
    def ioc_count(self) -> int:
        return sum(len(values) for values in self.iocs.values() if isinstance(values, list))
