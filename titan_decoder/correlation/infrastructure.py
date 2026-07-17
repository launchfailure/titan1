"""Infrastructure reuse detection across analyses.

Flags network-infrastructure indicators (domains, URLs, public IPs,
certificates, …) that appear in more than one recorded analysis. Private
IP ranges are intentionally excluded: shared RFC 1918 addresses across
unrelated cases are noise, not reuse.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from .models import AnalysisRecord, EvidenceReference, stable_id

SCHEMA_VERSION = "infrastructure-reuse-v1.0"

# Indicator types that describe attacker infrastructure. Both singular and
# plural forms are accepted because report IOC keys are plural ("domains")
# while hand-built records often use singular ("domain").
INFRA_TYPES = frozenset(
    {
        "domain",
        "domains",
        "url",
        "urls",
        "ipv4_public",
        "ipv6",
        "ip",
        "ips",
        "certificate",
        "certificates",
        "ja3",
        "ja4",
        "asn",
        "nameserver",
        "whois_email",
    }
)


@dataclass(frozen=True)
class InfrastructureReuse:
    """One indicator observed in two or more analyses."""

    indicator_type: str
    normalized_value: str
    analysis_ids: tuple[str, ...]

    @property
    def reuse_id(self) -> str:
        return stable_id(
            "infrastructure-reuse",
            {
                "type": self.indicator_type,
                "value": self.normalized_value,
                "analyses": list(self.analysis_ids),
            },
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "reuse_id": self.reuse_id,
            "indicator_type": self.indicator_type,
            "normalized_value": self.normalized_value,
            "analysis_ids": list(self.analysis_ids),
            "reuse_count": len(self.analysis_ids),
            "references": [
                EvidenceReference(analysis_id, source="infrastructure").to_dict()
                for analysis_id in self.analysis_ids
            ],
        }


def detect_infrastructure_reuse(analyses: Iterable[AnalysisRecord]) -> dict[str, Any]:
    """Return every infrastructure indicator shared by two or more analyses."""

    index: dict[tuple[str, str], set[str]] = {}
    for analysis in analyses:
        for indicator in analysis.indicators:
            kind = indicator.indicator_type.lower()
            if kind not in INFRA_TYPES:
                continue
            key = (kind, indicator.normalized_value or indicator.value)
            index.setdefault(key, set()).add(analysis.analysis_id)

    results = [
        InfrastructureReuse(kind, value, tuple(sorted(ids)))
        for (kind, value), ids in index.items()
        if len(ids) > 1
    ]
    results.sort(
        key=lambda item: (
            -len(item.analysis_ids),
            item.indicator_type,
            item.normalized_value,
        )
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "reuse_count": len(results),
        "reused_infrastructure": [item.to_dict() for item in results],
    }
