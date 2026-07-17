"""Campaign clustering over recorded analyses.

Builds the pairwise relationship graph with the deterministic
:class:`RelationshipScorer`, keeps edges at or above a score floor, and
returns the connected components as campaigns. Campaign identifiers are
stable digests of the sorted member set, so re-running over the same
database yields identical output.
"""

from __future__ import annotations

from typing import Any, Iterable

from .models import AnalysisRecord, Relationship, stable_id
from .relationships import RelationshipScorer

SCHEMA_VERSION = "campaign-clusters-v1.0"


def _confidence(strongest_score: float) -> str:
    if strongest_score >= 0.75:
        return "high"
    if strongest_score >= 0.45:
        return "medium"
    return "low"


def cluster_campaigns(
    analyses: Iterable[AnalysisRecord],
    *,
    minimum_score: float = 0.45,
    scorer: RelationshipScorer | None = None,
) -> dict[str, Any]:
    """Cluster analyses into campaigns via connected relationship components."""

    if not 0.0 <= minimum_score <= 1.0:
        raise ValueError("minimum_score must be between 0 and 1")

    records = tuple(sorted(analyses, key=lambda record: record.analysis_id))
    scorer = scorer or RelationshipScorer()

    graph: dict[str, set[str]] = {record.analysis_id: set() for record in records}
    edges: list[Relationship] = []
    for index, left in enumerate(records):
        for right in records[index + 1 :]:
            relationship = scorer.score(left, right)
            if relationship.score > 0.0 and relationship.score >= minimum_score:
                graph[left.analysis_id].add(right.analysis_id)
                graph[right.analysis_id].add(left.analysis_id)
                edges.append(relationship)

    seen: set[str] = set()
    campaigns: list[dict[str, Any]] = []
    for start in sorted(graph):
        if start in seen or not graph[start]:
            continue
        stack, members = [start], set()
        while stack:
            current = stack.pop()
            if current in seen:
                continue
            seen.add(current)
            members.add(current)
            stack.extend(sorted(graph[current] - seen, reverse=True))
        member_ids = tuple(sorted(members))
        relationships = [
            edge
            for edge in edges
            if edge.left_analysis_id in members and edge.right_analysis_id in members
        ]
        strongest = max((edge.score for edge in relationships), default=0.0)
        campaigns.append(
            {
                "campaign_id": stable_id("campaign", {"members": list(member_ids)}),
                "member_analysis_ids": list(member_ids),
                "relationship_ids": sorted(
                    edge.relationship_id for edge in relationships
                ),
                "relationship_count": len(relationships),
                "confidence": _confidence(strongest),
                "maximum_relationship_score": round(strongest, 6),
            }
        )

    campaigns.sort(key=lambda campaign: campaign["campaign_id"])
    return {
        "schema_version": SCHEMA_VERSION,
        "minimum_score": round(minimum_score, 6),
        "campaign_count": len(campaigns),
        "campaigns": campaigns,
    }
