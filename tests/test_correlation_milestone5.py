"""Tests for the Phase 5 milestone features: timeline correlation,
infrastructure reuse, shared payloads, attribution hints, campaign
clustering, and analyst views."""

import pytest

from titan_decoder.correlation.attribution import build_attribution_hints
from titan_decoder.correlation.campaigns import cluster_campaigns
from titan_decoder.correlation.infrastructure import detect_infrastructure_reuse
from titan_decoder.correlation.models import AnalysisRecord, IndicatorRecord
from titan_decoder.correlation.payload_similarity import (
    PayloadFingerprint,
    detect_shared_payloads,
)
from titan_decoder.correlation.timeline import TimelineEvent
from titan_decoder.correlation.timeline_correlation import correlate_timelines
from titan_decoder.correlation.views import analyst_summary, to_html, to_markdown


def _record(case_id: str, domain: str, attack_ids=("T1027",)) -> AnalysisRecord:
    return AnalysisRecord(
        analysis_id=case_id,
        root_hash=f"hash-{case_id}",
        indicators=(IndicatorRecord(case_id, "domains", domain),),
        attack_ids=attack_ids,
    )


def test_infrastructure_reuse_detects_shared_domain():
    analyses = (_record("a", "c2.test"), _record("b", "c2.test"))
    report = detect_infrastructure_reuse(analyses)
    assert report["reuse_count"] == 1
    reuse = report["reused_infrastructure"][0]
    assert reuse["indicator_type"] == "domains"
    assert reuse["normalized_value"] == "c2.test"
    assert reuse["analysis_ids"] == ["a", "b"]
    assert reuse["reuse_count"] == 2


def test_infrastructure_reuse_ignores_non_infra_and_unique_indicators():
    analyses = (
        AnalysisRecord(
            "a",
            "hash-a",
            indicators=(
                IndicatorRecord("a", "hashes", "deadbeef"),
                IndicatorRecord("a", "ipv4_private", "10.0.0.1"),
                IndicatorRecord("a", "domains", "only-here.test"),
            ),
        ),
        AnalysisRecord(
            "b",
            "hash-b",
            indicators=(
                IndicatorRecord("b", "hashes", "deadbeef"),
                IndicatorRecord("b", "ipv4_private", "10.0.0.1"),
            ),
        ),
    )
    report = detect_infrastructure_reuse(analyses)
    assert report["reuse_count"] == 0


def test_shared_payload_exact_hash_match():
    report = detect_shared_payloads(
        (
            PayloadFingerprint("a", "x", payload_hashes=("same",)),
            PayloadFingerprint("b", "y", payload_hashes=("same",)),
        )
    )
    assert report["match_count"] == 1
    match = report["matches"][0]
    assert match["score"] >= 0.55
    assert "exact_payload_hash" in match["reasons"]


def test_shared_payload_below_floor_excluded():
    report = detect_shared_payloads(
        (
            PayloadFingerprint("a", "x", decode_chain=("base64",)),
            PayloadFingerprint("b", "y", decode_chain=("base64",)),
        ),
        minimum_score=0.35,
    )
    assert report["match_count"] == 0


def test_shared_payload_rejects_bad_floor():
    with pytest.raises(ValueError):
        detect_shared_payloads((), minimum_score=1.5)


def test_timeline_correlation_links_shared_metadata():
    events = (
        TimelineEvent(
            "a",
            "2026-01-01T00:00:00Z",
            "dns_query",
            "query",
            metadata={"domain": "c2.test"},
        ),
        TimelineEvent(
            "b",
            "2026-01-01T00:01:00Z",
            "proxy_request",
            "connect",
            metadata={"domain": "c2.test"},
        ),
    )
    report = correlate_timelines(events, window_seconds=300)
    assert report["event_count"] == 2
    assert report["link_count"] == 1
    link = report["links"][0]
    assert link["reason"] == "shared_metadata:c2.test"
    assert 0.0 < link["score"] <= 1.0


def test_timeline_correlation_respects_window():
    events = (
        TimelineEvent(
            "a",
            "2026-01-01T00:00:00Z",
            "dns_query",
            "query",
            metadata={"domain": "c2.test"},
        ),
        TimelineEvent(
            "b",
            "2026-01-01T01:00:00Z",
            "dns_query",
            "query",
            metadata={"domain": "c2.test"},
        ),
    )
    assert correlate_timelines(events, window_seconds=300)["link_count"] == 0


def test_timeline_correlation_never_links_same_analysis():
    events = (
        TimelineEvent(
            "a",
            "2026-01-01T00:00:00Z",
            "dns_query",
            "query",
            metadata={"domain": "c2.test"},
        ),
        TimelineEvent(
            "a",
            "2026-01-01T00:00:30Z",
            "dns_query",
            "query",
            metadata={"domain": "c2.test"},
        ),
    )
    assert correlate_timelines(events, window_seconds=300)["link_count"] == 0


def test_timeline_correlation_rejects_negative_window():
    with pytest.raises(ValueError):
        correlate_timelines((), window_seconds=-1)


def test_attribution_hints_combine_evidence():
    analyses = (_record("a", "c2.test"), _record("b", "c2.test"))
    infra = detect_infrastructure_reuse(analyses)
    payloads = detect_shared_payloads(
        (
            PayloadFingerprint("a", "x", payload_hashes=("same",)),
            PayloadFingerprint("b", "y", payload_hashes=("same",)),
        )
    )
    hints = build_attribution_hints(analyses, infra, payloads)
    assert hints["hint_count"] == 1
    hint = hints["hints"][0]
    assert hint["confidence"] in {"medium", "high"}
    assert "infrastructure:domains" in hint["evidence"]
    assert "exact_payload_hash" in hint["evidence"]
    assert "shared_attack" in hint["evidence"]
    assert "lead" in hint["statement"]
    assert "not actor identity claims" in hints["disclaimer"]


def test_attribution_hints_empty_without_shared_evidence():
    analyses = (_record("a", "one.test"), _record("b", "two.test"))
    infra = detect_infrastructure_reuse(analyses)
    payloads = detect_shared_payloads(())
    hints = build_attribution_hints(analyses, infra, payloads)
    assert hints["hint_count"] == 0


def test_campaign_clustering_groups_connected_analyses():
    analyses = (
        _record("a", "c2.test"),
        _record("b", "c2.test"),
        _record("c", "unrelated.test", attack_ids=()),
    )
    report = cluster_campaigns(analyses, minimum_score=0.45)
    assert report["campaign_count"] == 1
    campaign = report["campaigns"][0]
    assert campaign["member_analysis_ids"] == ["a", "b"]
    assert campaign["relationship_count"] == 1
    assert campaign["confidence"] in {"medium", "high"}


def test_campaign_clustering_is_deterministic():
    analyses = (_record("a", "c2.test"), _record("b", "c2.test"))
    first = cluster_campaigns(analyses)
    second = cluster_campaigns(tuple(reversed(analyses)))
    assert first == second


def test_campaign_clustering_rejects_bad_floor():
    with pytest.raises(ValueError):
        cluster_campaigns((), minimum_score=2.0)


def test_analyst_views_render_all_sections():
    analyses = (_record("a", "c2.test"), _record("b", "c2.test"))
    infra = detect_infrastructure_reuse(analyses)
    result = {
        "correlation": {"subject_analysis_id": "b", "relationships": []},
        "campaigns": cluster_campaigns(analyses),
        "timeline_correlation": correlate_timelines(()),
        "infrastructure_reuse": infra,
        "shared_payloads": detect_shared_payloads(()),
        "attribution_hints": build_attribution_hints(analyses, infra, {"matches": []}),
    }
    view = analyst_summary(result)
    assert view["schema_version"] == "analyst-correlation-view-v1.0"
    assert view["subject_analysis_id"] == "b"

    markdown = to_markdown(view)
    assert "# Titan Phase 5 Correlation" in markdown
    assert "Infrastructure reuse: **1**" in markdown

    html = to_html(view)
    assert html.startswith("<!doctype html>")
    assert "application/json" in html
