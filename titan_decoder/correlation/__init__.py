"""Deterministic cross-case evidence correlation (Phase 5)."""

from .adapters import analysis_record_from_report, timeline_events_from_report
from .attribution import build_attribution_hints
from .campaigns import cluster_campaigns
from .database import CorrelationDatabase
from .engine import CorrelationEngine
from .infrastructure import detect_infrastructure_reuse
from .models import (
    AnalysisRecord,
    CorrelationEvidence,
    CorrelationReport,
    EvidenceReference,
    IndicatorRecord,
    Relationship,
    SCHEMA_VERSION,
    stable_id,
)
from .payload_similarity import (
    PayloadFingerprint,
    SharedPayload,
    detect_shared_payloads,
    fingerprint_from_report,
)
from .relationships import RelationshipScorer, score_relationship
from .service import analyze_milestone5, correlate_report, search_cases
from .timeline import TimelineEvent, normalize_timestamp, sort_timeline
from .timeline_correlation import TimelineLink, correlate_timelines
from .views import analyst_summary, to_html, to_markdown

__all__ = [
    "AnalysisRecord",
    "CorrelationDatabase",
    "CorrelationEngine",
    "CorrelationEvidence",
    "CorrelationReport",
    "EvidenceReference",
    "IndicatorRecord",
    "PayloadFingerprint",
    "Relationship",
    "RelationshipScorer",
    "SCHEMA_VERSION",
    "SharedPayload",
    "TimelineEvent",
    "TimelineLink",
    "analysis_record_from_report",
    "analyze_milestone5",
    "analyst_summary",
    "build_attribution_hints",
    "cluster_campaigns",
    "correlate_report",
    "correlate_timelines",
    "detect_infrastructure_reuse",
    "detect_shared_payloads",
    "fingerprint_from_report",
    "normalize_timestamp",
    "score_relationship",
    "search_cases",
    "sort_timeline",
    "stable_id",
    "timeline_events_from_report",
    "to_html",
    "to_markdown",
]
