"""The evidence ledger: stable, citable references into Titan reports.

The Local AI Analyst never sees raw reports. It sees an immutable ledger of
:class:`EvidenceItem` entries — nodes, signals, detections, IOCs, ATT&CK
techniques, risk facts, and correlation results — each with a deterministic
``evidence_id`` that answers cite. IDs are stable across runs so citations
in saved answers remain resolvable.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from typing import Any, Iterable, Mapping

MAX_EVIDENCE_ITEMS = 5000

# Node fields carried into the ledger. Includes both the engine's real key
# names (id/parent) and the generic ones (node_id/parent_id) so hand-built
# reports keep working.
_NODE_FIELDS = (
    "id",
    "node_id",
    "parent",
    "parent_id",
    "depth",
    "method",
    "decoder_used",
    "transformation",
    "content_type",
    "artifact_name",
    "sha256",
    "content_preview",
    "decode_score",
    "score",
)


@dataclass(frozen=True)
class EvidenceItem:
    """One citable fact extracted from a report."""

    evidence_id: str
    kind: str
    title: str
    value: Any
    path: str
    analysis_id: str = ""
    node_id: str = ""
    source_id: str = ""

    def citation(self) -> str:
        return f"[{self.evidence_id}]"

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "kind": self.kind,
            "title": self.title,
            "value": self.value,
            "path": self.path,
            "analysis_id": self.analysis_id,
            "node_id": self.node_id,
            "source_id": self.source_id,
        }


def _hashed_id(kind: str, path: str, value: Any) -> str:
    payload = json.dumps(
        {"kind": kind, "path": path, "value": value},
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return f"{kind}:{sha256(payload.encode()).hexdigest()[:12]}"


class EvidenceIndex:
    """Immutable, deterministic ledger over one or more reports."""

    def __init__(self, items: Iterable[EvidenceItem], max_items: int = MAX_EVIDENCE_ITEMS):
        self.items = tuple(
            sorted(items, key=lambda x: (x.kind, x.path, x.evidence_id))[:max_items]
        )
        self.by_id = {item.evidence_id: item for item in self.items}

    @classmethod
    def from_reports(
        cls,
        reports: Iterable[Mapping[str, Any]],
        max_items: int = MAX_EVIDENCE_ITEMS,
    ) -> "EvidenceIndex":
        reports = tuple(reports)
        # Natural IDs (node numbers, rule IDs) collide across reports; a
        # report-ordinal prefix keeps every citation unambiguous when more
        # than one report is loaded. Single-report ledgers keep short IDs.
        multi = len(reports) > 1

        def scoped(kind: str, natural: str, ordinal: int) -> str:
            return f"{kind}:{ordinal}:{natural}" if multi else f"{kind}:{natural}"

        items: list[EvidenceItem] = []
        for rn, report in enumerate(reports):
            meta = report.get("meta") or {}
            analysis_id = str(
                meta.get("analysis_id")
                or report.get("analysis_id")
                or report.get("root_hash")
                or f"report-{rn}"
            )

            risk = report.get("risk_assessment") or report.get("risk") or {}
            for key in ("risk_level", "level", "risk_score", "score", "summary"):
                if key in risk:
                    path = f"reports[{rn}].risk.{key}"
                    items.append(
                        EvidenceItem(
                            _hashed_id("risk", path, risk[key]),
                            "risk",
                            f"Risk {key.replace('_', ' ')}",
                            risk[key],
                            path,
                            analysis_id,
                        )
                    )

            intelligence = report.get("intelligence") or {}
            for key in ("classification", "intelligence_score", "confidence", "recommendation"):
                if key in intelligence:
                    path = f"reports[{rn}].intelligence.{key}"
                    items.append(
                        EvidenceItem(
                            _hashed_id("intelligence", path, intelligence[key]),
                            "intelligence",
                            key.replace("_", " ").title(),
                            intelligence[key],
                            path,
                            analysis_id,
                        )
                    )
            for i, signal in enumerate(intelligence.get("signals") or []):
                if isinstance(signal, Mapping):
                    code = str(signal.get("code") or f"signal-{i}")
                    items.append(
                        EvidenceItem(
                            scoped("signal", code, rn),
                            "signal",
                            str(signal.get("summary") or code),
                            dict(signal),
                            f"reports[{rn}].intelligence.signals[{i}]",
                            analysis_id,
                            source_id=code,
                        )
                    )

            for i, node in enumerate(report.get("nodes") or []):
                if not isinstance(node, Mapping):
                    continue
                node_id = str(
                    node.get("id") if node.get("id") is not None else node.get("node_id", i)
                )
                value = {
                    key: node.get(key)
                    for key in _NODE_FIELDS
                    if node.get(key) is not None
                }
                items.append(
                    EvidenceItem(
                        scoped("node", node_id, rn),
                        "node",
                        str(
                            node.get("method")
                            or node.get("decoder_used")
                            or node.get("transformation")
                            or "input"
                        ),
                        value,
                        f"reports[{rn}].nodes[{i}]",
                        analysis_id,
                        node_id=node_id,
                    )
                )

            for kind, values in sorted((report.get("iocs") or {}).items()):
                if not isinstance(values, list):
                    continue
                for i, raw in enumerate(values):
                    indicator = (
                        raw.get("value") or raw.get("normalized_value")
                        if isinstance(raw, Mapping)
                        else raw
                    )
                    if indicator is None or not str(indicator):
                        continue
                    digest = sha256(str(indicator).encode()).hexdigest()[:10]
                    items.append(
                        EvidenceItem(
                            f"ioc:{kind}:{digest}",  # content-hashed: shared IOCs share IDs
                            "ioc",
                            str(kind),
                            str(indicator),
                            f"reports[{rn}].iocs.{kind}[{i}]",
                            analysis_id,
                        )
                    )

            for i, detection in enumerate(report.get("detections") or []):
                if not isinstance(detection, Mapping):
                    continue
                rule_id = str(detection.get("rule_id") or detection.get("id") or i)
                items.append(
                    EvidenceItem(
                        scoped("detection", rule_id, rn),
                        "detection",
                        str(detection.get("name") or rule_id),
                        dict(detection),
                        f"reports[{rn}].detections[{i}]",
                        analysis_id,
                        source_id=rule_id,
                    )
                )

            threat = report.get("threat_intelligence") or {}
            for i, technique in enumerate(threat.get("techniques") or []):
                if not isinstance(technique, Mapping):
                    continue
                technique_id = str(
                    technique.get("technique_id")
                    or technique.get("attack_id")
                    or technique.get("id")
                    or i
                )
                items.append(
                    EvidenceItem(
                        scoped("attack", technique_id, rn),
                        "attack",
                        str(technique.get("name") or technique_id),
                        dict(technique),
                        f"reports[{rn}].threat_intelligence.techniques[{i}]",
                        analysis_id,
                        source_id=technique_id,
                    )
                )

            correlation = report.get("correlation") or {}
            for i, relationship in enumerate(correlation.get("relationships") or []):
                if not isinstance(relationship, Mapping):
                    continue
                rel_id = str(relationship.get("relationship_id") or i)
                items.append(
                    EvidenceItem(
                        scoped("relationship", rel_id[:60], rn),
                        "relationship",
                        "Cross-case relationship",
                        dict(relationship),
                        f"reports[{rn}].correlation.relationships[{i}]",
                        analysis_id,
                        source_id=rel_id,
                    )
                )
            for i, hint in enumerate((report.get("attribution_hints") or {}).get("hints") or []):
                if not isinstance(hint, Mapping):
                    continue
                hint_id = str(hint.get("hint_id") or i)
                items.append(
                    EvidenceItem(
                        scoped("hint", hint_id[:60], rn),
                        "attribution_hint",
                        "Attribution hint",
                        dict(hint),
                        f"reports[{rn}].attribution_hints.hints[{i}]",
                        analysis_id,
                        source_id=hint_id,
                    )
                )
        return cls(items, max_items=max_items)

    def select(
        self,
        kinds: Iterable[str] = (),
        terms: Iterable[str] = (),
        limit: int = 80,
    ) -> tuple[EvidenceItem, ...]:
        """Deterministically select a bounded, relevance-ranked subset."""

        kind_set = set(kinds)
        term_set = {str(term).lower() for term in terms if str(term).strip()}
        scored: list[tuple[int, EvidenceItem]] = []
        for item in self.items:
            if kind_set and item.kind not in kind_set:
                continue
            haystack = json.dumps(item.to_dict(), sort_keys=True, default=str).lower()
            matches = sum(term in haystack for term in term_set)
            if term_set and not matches:
                continue
            scored.append((matches, item))
        scored.sort(key=lambda pair: (-pair[0], pair[1].kind, pair[1].path))
        return tuple(item for _, item in scored[:limit])

    def context_json(self, items: Iterable[EvidenceItem]) -> str:
        return json.dumps([item.to_dict() for item in items], indent=2, default=str)
