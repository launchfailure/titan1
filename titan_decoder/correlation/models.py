"""Versioned data models for deterministic cross-case correlation."""

from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
import json
from typing import Any, Iterable, Mapping

SCHEMA_VERSION = "1.0"


def _stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def stable_id(namespace: str, payload: Mapping[str, Any]) -> str:
    """Return a deterministic identifier for *payload* within *namespace*."""

    digest = sha256(_stable_json(dict(payload)).encode("utf-8")).hexdigest()
    return f"{namespace}:{digest}"


def _sorted_unique(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(sorted({str(value) for value in values if str(value)}))


@dataclass(frozen=True)
class EvidenceReference:
    """Pointer from a correlation fact back to its source evidence."""

    analysis_id: str
    node_id: str | None = None
    evidence_id: str | None = None
    source: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"analysis_id": self.analysis_id}
        if self.node_id is not None:
            data["node_id"] = self.node_id
        if self.evidence_id is not None:
            data["evidence_id"] = self.evidence_id
        if self.source is not None:
            data["source"] = self.source
        return data


@dataclass(frozen=True)
class IndicatorRecord:
    """Canonical indicator attached to one analysis."""

    analysis_id: str
    indicator_type: str
    value: str
    references: tuple[EvidenceReference, ...] = field(default_factory=tuple)
    normalized_value: str | None = None

    def __post_init__(self) -> None:
        if not self.analysis_id:
            raise ValueError("analysis_id must not be empty")
        if not self.indicator_type:
            raise ValueError("indicator_type must not be empty")
        if not self.value:
            raise ValueError("value must not be empty")

        object.__setattr__(self, "indicator_type", self.indicator_type.strip().lower())
        object.__setattr__(self, "normalized_value", self.normalized_value or self.value.strip())
        object.__setattr__(
            self,
            "references",
            tuple(sorted(self.references, key=lambda ref: _stable_json(ref.to_dict()))),
        )

    @property
    def indicator_id(self) -> str:
        return stable_id(
            "indicator",
            {"type": self.indicator_type, "value": self.normalized_value},
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "indicator_id": self.indicator_id,
            "analysis_id": self.analysis_id,
            "type": self.indicator_type,
            "value": self.value,
            "normalized_value": self.normalized_value,
            "references": [reference.to_dict() for reference in self.references],
        }


@dataclass(frozen=True)
class AnalysisRecord:
    """Persistence-safe representation of one Titan analysis."""

    analysis_id: str
    root_hash: str
    created_at: str | None = None
    indicators: tuple[IndicatorRecord, ...] = field(default_factory=tuple)
    attack_ids: tuple[str, ...] = field(default_factory=tuple)
    threat_tags: tuple[str, ...] = field(default_factory=tuple)
    decode_chain: tuple[str, ...] = field(default_factory=tuple)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.analysis_id:
            raise ValueError("analysis_id must not be empty")
        if not self.root_hash:
            raise ValueError("root_hash must not be empty")

        object.__setattr__(
            self,
            "indicators",
            tuple(
                sorted(
                    self.indicators,
                    key=lambda item: (item.indicator_type, item.normalized_value or ""),
                )
            ),
        )
        object.__setattr__(self, "attack_ids", _sorted_unique(self.attack_ids))
        object.__setattr__(self, "threat_tags", _sorted_unique(self.threat_tags))
        object.__setattr__(self, "decode_chain", tuple(str(item) for item in self.decode_chain))
        object.__setattr__(self, "metadata", dict(self.metadata))

    def to_dict(self) -> dict[str, Any]:
        return {
            "analysis_id": self.analysis_id,
            "root_hash": self.root_hash,
            "created_at": self.created_at,
            "indicators": [indicator.to_dict() for indicator in self.indicators],
            "attack_ids": list(self.attack_ids),
            "threat_tags": list(self.threat_tags),
            "decode_chain": list(self.decode_chain),
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "AnalysisRecord":
        indicators = tuple(
            IndicatorRecord(
                analysis_id=str(item["analysis_id"]),
                indicator_type=str(item["type"]),
                value=str(item["value"]),
                normalized_value=str(item.get("normalized_value") or item["value"]),
                references=tuple(
                    EvidenceReference(
                        analysis_id=str(ref["analysis_id"]),
                        node_id=ref.get("node_id"),
                        evidence_id=ref.get("evidence_id"),
                        source=ref.get("source"),
                    )
                    for ref in item.get("references", [])
                ),
            )
            for item in data.get("indicators", [])
        )
        return cls(
            analysis_id=str(data["analysis_id"]),
            root_hash=str(data["root_hash"]),
            created_at=data.get("created_at"),
            indicators=indicators,
            attack_ids=tuple(data.get("attack_ids", [])),
            threat_tags=tuple(data.get("threat_tags", [])),
            decode_chain=tuple(data.get("decode_chain", [])),
            metadata=dict(data.get("metadata", {})),
        )


@dataclass(frozen=True)
class CorrelationEvidence:
    """One explainable contribution to a relationship score."""

    kind: str
    key: str
    weight: float
    references: tuple[EvidenceReference, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if not self.kind or not self.key:
            raise ValueError("correlation evidence kind and key must not be empty")
        if not 0.0 <= self.weight <= 1.0:
            raise ValueError("correlation evidence weight must be between 0 and 1")
        object.__setattr__(
            self,
            "references",
            tuple(sorted(self.references, key=lambda ref: _stable_json(ref.to_dict()))),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "key": self.key,
            "weight": round(self.weight, 6),
            "references": [reference.to_dict() for reference in self.references],
        }


@dataclass(frozen=True)
class Relationship:
    """Deterministic relationship between two analyses."""

    left_analysis_id: str
    right_analysis_id: str
    score: float
    confidence: str
    evidence: tuple[CorrelationEvidence, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if self.left_analysis_id == self.right_analysis_id:
            raise ValueError("relationship endpoints must be different")
        left, right = sorted((self.left_analysis_id, self.right_analysis_id))
        object.__setattr__(self, "left_analysis_id", left)
        object.__setattr__(self, "right_analysis_id", right)

        if not 0.0 <= self.score <= 1.0:
            raise ValueError("relationship score must be between 0 and 1")
        if self.confidence not in {"none", "low", "medium", "high"}:
            raise ValueError("unsupported relationship confidence")

        object.__setattr__(
            self,
            "evidence",
            tuple(sorted(self.evidence, key=lambda item: (item.kind, item.key))),
        )

    @property
    def relationship_id(self) -> str:
        return stable_id(
            "relationship",
            {
                "left": self.left_analysis_id,
                "right": self.right_analysis_id,
                "evidence": [item.to_dict() for item in self.evidence],
            },
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "relationship_id": self.relationship_id,
            "left_analysis_id": self.left_analysis_id,
            "right_analysis_id": self.right_analysis_id,
            "score": round(self.score, 6),
            "confidence": self.confidence,
            "evidence": [item.to_dict() for item in self.evidence],
        }


@dataclass(frozen=True)
class CorrelationReport:
    """Versioned output contract for Phase 5 correlation results."""

    subject_analysis_id: str
    relationships: tuple[Relationship, ...] = field(default_factory=tuple)
    generated_at: str | None = None
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "relationships",
            tuple(sorted(self.relationships, key=lambda item: item.relationship_id)),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "subject_analysis_id": self.subject_analysis_id,
            "generated_at": self.generated_at,
            "relationships": [relationship.to_dict() for relationship in self.relationships],
        }
