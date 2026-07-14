"""End-to-end Phase 5 orchestration for one analysis report.

``analyze_milestone5`` is the single entry point used by the CLI: it
normalizes the subject report, correlates it against the local database,
clusters campaigns, correlates timelines, detects infrastructure reuse and
shared payloads, and derives attribution hints plus the analyst view.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable, Mapping

from .adapters import analysis_record_from_report, timeline_events_from_report
from .attribution import build_attribution_hints
from .campaigns import cluster_campaigns
from .database import CorrelationDatabase
from .engine import CorrelationEngine
from .infrastructure import detect_infrastructure_reuse
from .payload_similarity import detect_shared_payloads, fingerprint_from_report
from .timeline_correlation import correlate_timelines
from .views import analyst_summary

SCHEMA_VERSION = "milestone-5-report-v1.0"


def analyze_milestone5(
    report: Mapping[str, Any],
    database_path: str | Path,
    *,
    prior_reports: Iterable[Mapping[str, Any]] = (),
    minimum_relationship_score: float = 0.0,
    minimum_campaign_score: float = 0.45,
    minimum_payload_score: float = 0.35,
    timeline_window_seconds: float = 300.0,
    record_subject: bool = True,
) -> dict[str, Any]:
    """Run the full Phase 5 correlation suite for one report.

    Relationship scoring, campaign clustering, infrastructure reuse, and
    attribution hints operate on the persisted analysis records (including
    the subject). Payload fingerprints and timeline events need node- and
    event-level detail that is not persisted, so they come from the subject
    report plus any ``prior_reports`` supplied by the caller.
    """

    subject = analysis_record_from_report(report)
    prior_reports = tuple(prior_reports)

    with CorrelationDatabase(database_path) as database:
        correlation = CorrelationEngine(
            database, minimum_score=minimum_relationship_score
        ).correlate(subject, record_subject=record_subject)
        analyses = list(database.iter_analyses())
        if not record_subject:
            analyses.append(subject)

    reports = prior_reports + (report,)
    infrastructure = detect_infrastructure_reuse(analyses)
    shared_payloads = detect_shared_payloads(
        (fingerprint_from_report(item) for item in reports),
        minimum_score=minimum_payload_score,
    )
    events = [
        event for item in reports for event in timeline_events_from_report(item)
    ]
    timeline = correlate_timelines(events, window_seconds=timeline_window_seconds)

    result: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "correlation": correlation.to_dict(),
        "campaigns": cluster_campaigns(analyses, minimum_score=minimum_campaign_score),
        "timeline_correlation": timeline,
        "infrastructure_reuse": infrastructure,
        "shared_payloads": shared_payloads,
        "attribution_hints": build_attribution_hints(
            analyses, infrastructure, shared_payloads
        ),
    }
    result["analyst_view"] = analyst_summary(result)
    return result


def correlate_report(
    report: Mapping[str, Any],
    database_path: str | Path,
    *,
    minimum_score: float = 0.0,
    record_subject: bool = True,
) -> dict[str, Any]:
    """Convenience wrapper returning only the relationship correlation."""

    return analyze_milestone5(
        report,
        database_path,
        minimum_relationship_score=minimum_score,
        record_subject=record_subject,
    )["correlation"]
