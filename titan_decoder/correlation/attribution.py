"""Evidence-backed attribution hints.

Combines infrastructure reuse, shared payloads, and ATT&CK/tag overlap into
per-pair hints. A hint is an investigative lead — the output deliberately
carries a disclaimer and never names an actor.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

from .models import AnalysisRecord, stable_id

SCHEMA_VERSION = "attribution-hints-v1.0"

DISCLAIMER = (
    "Attribution hints are evidence-backed investigative leads, "
    "not actor identity claims."
)


def _confidence(score: float) -> str:
    if score >= 0.75:
        return "high"
    if score >= 0.45:
        return "medium"
    return "low"


def build_attribution_hints(
    analyses: Iterable[AnalysisRecord],
    infrastructure_report: Mapping[str, Any],
    payload_report: Mapping[str, Any],
) -> dict[str, Any]:
    """Build ranked attribution hints for analysis pairs with shared evidence."""

    records = {record.analysis_id: record for record in analyses}
    pairs: dict[tuple[str, str], dict[str, Any]] = {}

    for item in infrastructure_report.get("reused_infrastructure") or ():
        ids = sorted(item.get("analysis_ids") or ())
        for index, left in enumerate(ids):
            for right in ids[index + 1 :]:
                pair = pairs.setdefault((left, right), {"evidence": [], "score": 0.0})
                pair["evidence"].append(
                    "infrastructure:" + str(item.get("indicator_type"))
                )
                pair["score"] += 0.35

    for item in payload_report.get("matches") or ():
        key = tuple(sorted((item["left_analysis_id"], item["right_analysis_id"])))
        pair = pairs.setdefault(key, {"evidence": [], "score": 0.0})
        pair["evidence"].extend(item.get("reasons") or ())
        pair["score"] += 0.40 * float(item.get("score", 0.0))

    hints: list[dict[str, Any]] = []
    for (left, right), data in pairs.items():
        if left in records and right in records:
            attack_overlap = set(records[left].attack_ids) & set(
                records[right].attack_ids
            )
            tag_overlap = set(records[left].threat_tags) & set(
                records[right].threat_tags
            )
            if attack_overlap:
                data["score"] += min(0.15, 0.05 * len(attack_overlap))
                data["evidence"].append("shared_attack")
            if tag_overlap:
                data["score"] += min(0.10, 0.025 * len(tag_overlap))
                data["evidence"].append("shared_threat_tag")
        score = min(1.0, data["score"])
        evidence = tuple(sorted(set(data["evidence"])))
        hints.append(
            {
                "hint_id": stable_id(
                    "attribution-hint",
                    {"left": left, "right": right, "evidence": list(evidence)},
                ),
                "left_analysis_id": left,
                "right_analysis_id": right,
                "confidence": _confidence(score),
                "score": round(score, 6),
                "evidence": list(evidence),
                "statement": (
                    "Analyses share forensic characteristics; this is a lead, "
                    "not definitive attribution."
                ),
            }
        )

    hints.sort(key=lambda hint: (-hint["score"], hint["hint_id"]))
    return {
        "schema_version": SCHEMA_VERSION,
        "hint_count": len(hints),
        "hints": hints,
        "disclaimer": DISCLAIMER,
    }
