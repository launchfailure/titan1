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

    Every feature operates cross-case against the correlation database:
    analysis records power relationship scoring, campaign clustering,
    infrastructure reuse, and attribution hints, while persisted payload
    fingerprints and timeline events power shared-payload and timeline
    correlation. ``prior_reports`` remains supported for callers that
    correlate reports without recording them.
    """

    subject = analysis_record_from_report(report)
    subject_fingerprint = fingerprint_from_report(report)
    subject_events = timeline_events_from_report(report)
    prior_reports = tuple(prior_reports)

    with CorrelationDatabase(database_path) as database:
        correlation = CorrelationEngine(
            database, minimum_score=minimum_relationship_score
        ).correlate(subject, record_subject=record_subject)
        if record_subject:
            database.record_fingerprint(subject_fingerprint)
            database.record_timeline_events(subject.analysis_id, subject_events)
        analyses = list(database.iter_analyses())
        stored_fingerprints = database.iter_fingerprints()
        stored_events = database.iter_timeline_events()
        if not record_subject:
            analyses.append(subject)

    # Merge persisted state with in-process reports, deduplicating so a
    # report that was also recorded is not counted twice. Later sources win
    # for fingerprints (the in-process report is the freshest view).
    fingerprints = {item.analysis_id: item for item in stored_fingerprints}
    for item in prior_reports:
        fingerprint = fingerprint_from_report(item)
        fingerprints[fingerprint.analysis_id] = fingerprint
    fingerprints[subject_fingerprint.analysis_id] = subject_fingerprint

    events = {event.event_id: event for event in stored_events}
    for item in prior_reports:
        for event in timeline_events_from_report(item):
            events[event.event_id] = event
    for event in subject_events:
        events[event.event_id] = event

    infrastructure = detect_infrastructure_reuse(analyses)
    shared_payloads = detect_shared_payloads(
        fingerprints.values(), minimum_score=minimum_payload_score
    )
    timeline = correlate_timelines(
        events.values(), window_seconds=timeline_window_seconds
    )

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


def search_cases(
    database_path: str | Path,
    queries: Iterable[str],
) -> dict[str, Any]:
    """Search the correlation database for indicators across recorded cases.

    Each query is either a bare value (searched across every indicator type)
    or ``type:value`` (restricted to one type, e.g. ``domains:c2.test``).
    Matching is exact on the normalized value and case-insensitive. Results
    include the stored indicator payloads with their evidence references.
    """

    results = []
    with CorrelationDatabase(database_path) as database:
        for query in queries:
            text = str(query).strip()
            if not text:
                continue
            indicator_type: str | None = None
            value = text
            head, separator, tail = text.partition(":")
            # "type:value" splits on the first colon; URL queries like
            # "https://x" must not be treated as a type filter.
            if (
                separator
                and tail
                and head.replace("_", "").isalnum()
                and not tail.startswith("//")
            ):
                indicator_type, value = head, tail
            matches = database.search_indicators(value, indicator_type)
            analysis_ids = sorted({item["analysis_id"] for item in matches})
            results.append(
                {
                    "query": text,
                    "indicator_type": indicator_type,
                    "value": value,
                    "match_count": len(matches),
                    "analysis_ids": analysis_ids,
                    "matches": list(matches),
                }
            )
    return {
        "schema_version": "correlation-search-v1.0",
        "database": str(database_path),
        "results": results,
    }


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
