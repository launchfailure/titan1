"""Typed, serialization-friendly threat-intelligence models."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List


def _clamp_confidence(value: float) -> float:
    return round(max(0.0, min(1.0, float(value))), 2)


@dataclass(frozen=True)
class AttackTechniqueFinding:
    technique_id: str
    name: str
    tactics: List[str]
    confidence: float
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    source_rules: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "name": self.name,
            "tactics": sorted(set(self.tactics)),
            "confidence": _clamp_confidence(self.confidence),
            "evidence": list(self.evidence),
            "source_rules": sorted(set(self.source_rules)),
        }


@dataclass(frozen=True)
class LOLBinFinding:
    name: str
    executable: str
    technique_ids: List[str]
    confidence: float
    node_ids: List[Any] = field(default_factory=list)
    matched_terms: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "executable": self.executable,
            "technique_ids": sorted(set(self.technique_ids)),
            "confidence": _clamp_confidence(self.confidence),
            "node_ids": list(dict.fromkeys(self.node_ids)),
            "matched_terms": sorted(set(self.matched_terms)),
        }


@dataclass(frozen=True)
class MalwareTag:
    tag: str
    category: str
    confidence: float
    reasons: List[str] = field(default_factory=list)
    node_ids: List[Any] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tag": self.tag,
            "category": self.category,
            "confidence": _clamp_confidence(self.confidence),
            "reasons": list(dict.fromkeys(self.reasons)),
            "node_ids": list(dict.fromkeys(self.node_ids)),
        }


@dataclass(frozen=True)
class ThreatAssessment:
    version: str
    catalog_version: str
    techniques: List[AttackTechniqueFinding]
    tactics: List[str]
    lolbins: List[LOLBinFinding]
    malware_tags: List[MalwareTag]
    relationships: List[Dict[str, Any]]
    confidence: float
    summary: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "catalog_version": self.catalog_version,
            "techniques": [item.to_dict() for item in self.techniques],
            "tactics": sorted(set(self.tactics)),
            "lolbins": [item.to_dict() for item in self.lolbins],
            "malware_tags": [item.to_dict() for item in self.malware_tags],
            "relationships": list(self.relationships),
            "confidence": _clamp_confidence(self.confidence),
            "summary": self.summary,
        }
