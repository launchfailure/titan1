"""Report loading and summaries for the Analyst Workbench.

The workbench sits above the deterministic engine: it loads completed Titan
JSON reports read-only and never reinterprets or alters forensic findings.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any

MAX_REPORT_BYTES = 200 * 1024 * 1024


@dataclass(frozen=True)
class ReportSummary:
    """Header-level facts about one loaded report."""

    path: str
    analysis_id: str
    root_hash: str
    node_count: int
    ioc_count: int
    detection_count: int
    risk_level: str
    risk_score: float
    classification: str
    campaign_count: int
    relationship_count: int


def _root_hash(data: dict[str, Any]) -> str:
    explicit = data.get("root_hash") or (data.get("meta") or {}).get("root_hash")
    if explicit:
        return str(explicit)
    for node in data.get("nodes") or []:
        if isinstance(node, dict) and node.get("parent") is None and node.get("sha256"):
            return str(node["sha256"])
    return ""


@dataclass
class TitanReport:
    """One loaded report: raw data plus its derived summary."""

    path: Path
    data: dict[str, Any]
    summary: ReportSummary

    @classmethod
    def load(cls, path: str | Path) -> "TitanReport":
        report_path = Path(path)
        if report_path.stat().st_size > MAX_REPORT_BYTES:
            raise ValueError(f"report exceeds {MAX_REPORT_BYTES} bytes")
        data = json.loads(report_path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("Titan report root must be a JSON object")

        meta = data.get("meta") or {}
        analysis_id = str(
            meta.get("analysis_id")
            or data.get("analysis_id")
            or data.get("root_hash")
            or report_path.stem
        )
        iocs = data.get("iocs") or {}
        risk = data.get("risk_assessment") or data.get("risk") or {}
        intelligence = data.get("intelligence") or {}
        campaigns = data.get("campaigns") or {}
        correlation = data.get("correlation") or {}
        summary = ReportSummary(
            path=str(report_path),
            analysis_id=analysis_id,
            root_hash=_root_hash(data),
            node_count=int(data.get("node_count") or len(data.get("nodes") or [])),
            ioc_count=sum(len(v) for v in iocs.values() if isinstance(v, list)),
            detection_count=len(data.get("detections") or []),
            risk_level=str(risk.get("risk_level") or risk.get("level") or "unknown"),
            risk_score=float(risk.get("risk_score") or risk.get("score") or 0.0),
            classification=str(intelligence.get("classification") or "unclassified"),
            campaign_count=int(campaigns.get("campaign_count") or 0),
            relationship_count=len(correlation.get("relationships") or []),
        )
        return cls(report_path, data, summary)

    # -- accessors -----------------------------------------------------------

    def nodes(self) -> list[dict[str, Any]]:
        return [node for node in self.data.get("nodes") or [] if isinstance(node, dict)]

    def node_by_id(self, node_id: Any) -> "dict[str, Any] | None":
        wanted = str(node_id)
        for node in self.nodes():
            if str(node.get("id")) == wanted or str(node.get("node_id")) == wanted:
                return node
        return None

    def children_of(self, node_id: Any) -> list[dict[str, Any]]:
        wanted = str(node_id)
        return [node for node in self.nodes() if str(node.get("parent")) == wanted]

    def evidence(self) -> dict[str, Any]:
        evidence = self.data.get("evidence")
        return evidence if isinstance(evidence, dict) else {}

    def timeline(self) -> list[dict[str, Any]]:
        events = self.evidence().get("events")
        source = (
            events
            or self.data.get("timeline")
            or self.data.get("evidence_timeline")
            or []
        )
        return [event for event in source if isinstance(event, dict)]

    def indicators(self) -> list[tuple[str, str]]:
        result: list[tuple[str, str]] = []
        for kind, values in sorted((self.data.get("iocs") or {}).items()):
            if not isinstance(values, list):
                continue
            for value in values:
                if isinstance(value, dict):
                    value = value.get("value") or value.get("normalized_value")
                if value is not None and str(value):
                    result.append((str(kind), str(value)))
        return result

    def detections(self) -> list[dict[str, Any]]:
        return [
            item for item in self.data.get("detections") or [] if isinstance(item, dict)
        ]
