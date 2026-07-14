"""Deterministic, explainable relationship scoring."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .models import (
    AnalysisRecord,
    CorrelationEvidence,
    EvidenceReference,
    Relationship,
)

DEFAULT_WEIGHTS = {
    "shared_indicator": 0.50,
    "shared_attack": 0.20,
    "shared_threat_tag": 0.15,
    "decode_chain": 0.15,
}


def _confidence(score: float) -> str:
    if score >= 0.75:
        return "high"
    if score >= 0.45:
        return "medium"
    if score > 0.0:
        return "low"
    return "none"


def _jaccard(left: Iterable[str], right: Iterable[str]) -> float:
    left_set = set(left)
    right_set = set(right)
    union = left_set | right_set
    if not union:
        return 0.0
    return len(left_set & right_set) / len(union)


@dataclass(frozen=True)
class RelationshipScorer:
    """Score relationships using fixed, bounded feature weights."""

    shared_indicator_weight: float = DEFAULT_WEIGHTS["shared_indicator"]
    shared_attack_weight: float = DEFAULT_WEIGHTS["shared_attack"]
    shared_threat_tag_weight: float = DEFAULT_WEIGHTS["shared_threat_tag"]
    decode_chain_weight: float = DEFAULT_WEIGHTS["decode_chain"]

    def score(self, left: AnalysisRecord, right: AnalysisRecord) -> Relationship:
        evidence: list[CorrelationEvidence] = []

        left_indicators = {
            (item.indicator_type, item.normalized_value or item.value): item
            for item in left.indicators
        }
        right_indicators = {
            (item.indicator_type, item.normalized_value or item.value): item
            for item in right.indicators
        }
        shared_indicators = sorted(set(left_indicators) & set(right_indicators))
        indicator_component = 0.0
        if shared_indicators:
            denominator = max(len(left_indicators), len(right_indicators), 1)
            indicator_component = min(1.0, len(shared_indicators) / denominator)
            per_indicator = self.shared_indicator_weight / len(shared_indicators)
            for indicator_type, value in shared_indicators:
                refs = (
                    EvidenceReference(left.analysis_id, source="indicator"),
                    EvidenceReference(right.analysis_id, source="indicator"),
                )
                evidence.append(
                    CorrelationEvidence(
                        kind="shared_indicator",
                        key=f"{indicator_type}:{value}",
                        weight=per_indicator,
                        references=refs,
                    )
                )

        shared_attack = sorted(set(left.attack_ids) & set(right.attack_ids))
        attack_component = _jaccard(left.attack_ids, right.attack_ids)
        for attack_id in shared_attack:
            evidence.append(
                CorrelationEvidence(
                    kind="shared_attack",
                    key=attack_id,
                    weight=self.shared_attack_weight / len(shared_attack),
                    references=(
                        EvidenceReference(left.analysis_id, source="attack"),
                        EvidenceReference(right.analysis_id, source="attack"),
                    ),
                )
            )

        shared_tags = sorted(set(left.threat_tags) & set(right.threat_tags))
        threat_component = _jaccard(left.threat_tags, right.threat_tags)
        for tag in shared_tags:
            evidence.append(
                CorrelationEvidence(
                    kind="shared_threat_tag",
                    key=tag,
                    weight=self.shared_threat_tag_weight / len(shared_tags),
                    references=(
                        EvidenceReference(left.analysis_id, source="threat_tag"),
                        EvidenceReference(right.analysis_id, source="threat_tag"),
                    ),
                )
            )

        decode_component = _jaccard(left.decode_chain, right.decode_chain)
        if decode_component:
            evidence.append(
                CorrelationEvidence(
                    kind="decode_chain",
                    key="shared_decode_transforms",
                    weight=self.decode_chain_weight * decode_component,
                    references=(
                        EvidenceReference(left.analysis_id, source="decode_chain"),
                        EvidenceReference(right.analysis_id, source="decode_chain"),
                    ),
                )
            )

        score = (
            self.shared_indicator_weight * indicator_component
            + self.shared_attack_weight * attack_component
            + self.shared_threat_tag_weight * threat_component
            + self.decode_chain_weight * decode_component
        )
        score = round(min(1.0, max(0.0, score)), 6)

        return Relationship(
            left_analysis_id=left.analysis_id,
            right_analysis_id=right.analysis_id,
            score=score,
            confidence=_confidence(score),
            evidence=tuple(evidence),
        )


def score_relationship(left: AnalysisRecord, right: AnalysisRecord) -> Relationship:
    """Convenience wrapper using the default deterministic scorer."""

    return RelationshipScorer().score(left, right)
