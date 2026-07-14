"""End-to-end tests for the Phase 5 service, report adapters, and CLI stage."""

import json

import pytest

from titan_decoder import cli
from titan_decoder.correlation.adapters import (
    analysis_record_from_report,
    timeline_events_from_report,
)
from titan_decoder.correlation.payload_similarity import fingerprint_from_report
from titan_decoder.correlation.service import analyze_milestone5, correlate_report


def _engine_style_report(analysis_id: str, domain: str, timestamp: str, sha256: str = "same"):
    """Report shaped like TitanEngine.run_analysis output plus evidence events."""

    return {
        "meta": {
            "tool": "Titan Decoder Engine",
            "analysis_id": analysis_id,
            "started_at": "2026-01-01T00:00:00+00:00",
        },
        "node_count": 2,
        "nodes": [
            {"id": 0, "parent": None, "depth": 0, "method": "SOURCE", "sha256": f"root-{analysis_id}"},
            {"id": 1, "parent": 0, "depth": 1, "method": "Base64", "decoder_used": "Base64", "sha256": sha256},
        ],
        "iocs": {"domains": [domain], "urls": [], "ipv4_private": ["10.0.0.1"]},
        "detections": [{"rule": "obfuscation", "attack_ids": ["T1027"]}],
        "threat_intelligence": {
            "techniques": [{"technique_id": "T1027"}],
            "malware_tags": ["obfuscated"],
        },
        "evidence": {
            "events": [
                {
                    "event_id": f"ev-{analysis_id}",
                    "event_type": "dns_query",
                    "timestamp": timestamp,
                    "source": "dns.log",
                    "extracted_by": "dns_parser",
                    "domain": domain,
                    "host": None,
                    "raw": {"nested": True},
                }
            ]
        },
    }


def test_analysis_record_from_engine_style_report():
    record = analysis_record_from_report(
        _engine_style_report("case-1", "c2.test", "2026-01-01T00:00:00Z")
    )
    assert record.analysis_id == "case-1"
    assert record.root_hash == "root-case-1"
    assert record.created_at == "2026-01-01T00:00:00+00:00"
    assert ("domains", "c2.test") in {
        (item.indicator_type, item.normalized_value) for item in record.indicators
    }
    assert record.attack_ids == ("T1027",)
    assert record.threat_tags == ("obfuscated",)
    assert record.decode_chain == ("SOURCE", "Base64")


def test_analysis_record_requires_identifier_and_root_hash():
    with pytest.raises(ValueError):
        analysis_record_from_report({"nodes": [{"parent": None, "sha256": "x"}]})
    with pytest.raises(ValueError):
        analysis_record_from_report({"meta": {"analysis_id": "a"}, "nodes": []})


def test_timeline_events_skip_none_metadata_and_bad_timestamps():
    report = _engine_style_report("case-1", "c2.test", "2026-01-01T00:00:00Z")
    report["evidence"]["events"].append(
        {"event_type": "dns_query", "timestamp": "not-a-time", "domain": "x.test"}
    )
    events = timeline_events_from_report(report)
    assert len(events) == 1
    event = events[0]
    assert event.kind == "dns_query"
    # None-valued fields and nested raw data must not leak into metadata,
    # otherwise cross-case matching would link events on shared "None".
    assert "host" not in event.metadata
    assert "raw" not in event.metadata
    assert event.metadata["domain"] == "c2.test"


def test_fingerprint_from_engine_style_report():
    fingerprint = fingerprint_from_report(
        _engine_style_report("case-1", "c2.test", "2026-01-01T00:00:00Z")
    )
    assert fingerprint.analysis_id == "case-1"
    assert fingerprint.root_hash == "root-case-1"
    assert "same" in fingerprint.payload_hashes
    assert fingerprint.decode_chain == ("SOURCE", "Base64")


def test_analyze_milestone5_end_to_end(tmp_path):
    db = tmp_path / "correlation.sqlite3"
    first = _engine_style_report("case-a", "c2.test", "2026-01-01T00:00:00Z")
    second = _engine_style_report("case-b", "c2.test", "2026-01-01T00:01:00Z")

    analyze_milestone5(first, db)
    result = analyze_milestone5(second, db, prior_reports=(first,))

    assert result["schema_version"] == "milestone-5-report-v1.0"
    assert len(result["correlation"]["relationships"]) == 1
    assert result["campaigns"]["campaign_count"] == 1
    assert result["timeline_correlation"]["link_count"] == 1
    assert result["infrastructure_reuse"]["reuse_count"] == 1
    assert result["shared_payloads"]["match_count"] == 1
    assert result["attribution_hints"]["hint_count"] == 1
    assert result["analyst_view"]["subject_analysis_id"] == "case-b"


def test_analyze_milestone5_is_deterministic(tmp_path):
    first = _engine_style_report("case-a", "c2.test", "2026-01-01T00:00:00Z")
    second = _engine_style_report("case-b", "c2.test", "2026-01-01T00:01:00Z")
    results = []
    for name in ("one.sqlite3", "two.sqlite3"):
        db = tmp_path / name
        analyze_milestone5(first, db)
        results.append(analyze_milestone5(second, db, prior_reports=(first,)))
    assert results[0] == results[1]


def test_analyze_milestone5_matches_json_schema(tmp_path):
    jsonschema = pytest.importorskip("jsonschema")
    referencing = pytest.importorskip("referencing")
    from pathlib import Path

    schemas_dir = Path(__file__).resolve().parents[1] / "schemas"
    milestone = json.loads(
        (schemas_dir / "milestone-5-report-v1.0.schema.json").read_text()
    )
    correlation = json.loads(
        (schemas_dir / "correlation-report-v1.0.schema.json").read_text()
    )
    registry = referencing.Registry().with_resources(
        [
            (milestone["$id"], referencing.Resource.from_contents(milestone)),
            (correlation["$id"], referencing.Resource.from_contents(correlation)),
        ]
    )
    validator = jsonschema.Draft202012Validator(milestone, registry=registry)

    db = tmp_path / "correlation.sqlite3"
    first = _engine_style_report("case-a", "c2.test", "2026-01-01T00:00:00Z")
    analyze_milestone5(first, db)
    result = analyze_milestone5(
        _engine_style_report("case-b", "c2.test", "2026-01-01T00:01:00Z"),
        db,
        prior_reports=(first,),
    )
    validator.validate(result)


def test_correlate_report_no_record_leaves_database_unchanged(tmp_path):
    db = tmp_path / "correlation.sqlite3"
    first = _engine_style_report("case-a", "c2.test", "2026-01-01T00:00:00Z")
    second = _engine_style_report("case-b", "c2.test", "2026-01-01T00:01:00Z")

    analyze_milestone5(first, db)
    correlation = correlate_report(second, db, record_subject=False)
    assert len(correlation["relationships"]) == 1

    # The subject was not recorded, so correlating it again still sees only
    # the first analysis.
    again = correlate_report(second, db, record_subject=False)
    assert len(again["relationships"]) == 1


def _cli_args(**over):
    args = cli.build_parser().parse_args([])
    for key, value in over.items():
        setattr(args, key, value)
    return args


def test_cli_parser_phase5_defaults():
    args = cli.build_parser().parse_args(["--file", "x.bin"])
    assert args.correlation_db is None
    assert args.correlation_min_score == 0.0
    assert args.campaign_min_score == 0.45
    assert args.shared_payload_min_score == 0.35
    assert args.timeline_window_seconds == 300.0
    assert args.analyst_correlation_format == "json"


def test_cli_phase5_stage_noop_without_flags():
    report = {"meta": {"analysis_id": "case-a"}}
    assert cli.run_phase5_correlation_stage(_cli_args(), report) == 0
    assert "correlation" not in report


def test_cli_phase5_stage_writes_outputs(tmp_path, capsys):
    db = tmp_path / "correlation.sqlite3"
    first = _engine_style_report("case-a", "c2.test", "2026-01-01T00:00:00Z")
    analyze_milestone5(first, db)

    report = _engine_style_report("case-b", "c2.test", "2026-01-01T00:01:00Z")
    args = _cli_args(
        correlation_db=db,
        correlation_out=tmp_path / "correlation.json",
        campaign_out=tmp_path / "campaigns.json",
        infrastructure_reuse_out=tmp_path / "infra.json",
        shared_payload_out=tmp_path / "payloads.json",
        attribution_hints_out=tmp_path / "hints.json",
        analyst_correlation_out=tmp_path / "view.md",
        analyst_correlation_format="markdown",
        quiet=True,
    )
    assert cli.run_phase5_correlation_stage(args, report) == 0

    # Sections are embedded in the report for downstream output stages.
    assert len(report["correlation"]["relationships"]) == 1
    assert report["campaigns"]["campaign_count"] == 1

    correlation = json.loads((tmp_path / "correlation.json").read_text())
    assert correlation["subject_analysis_id"] == "case-b"
    assert json.loads((tmp_path / "campaigns.json").read_text())["campaign_count"] == 1
    assert json.loads((tmp_path / "infra.json").read_text())["reuse_count"] == 1
    assert json.loads((tmp_path / "payloads.json").read_text())["match_count"] == 0
    hints = json.loads((tmp_path / "hints.json").read_text())
    assert hints["hint_count"] == 1
    assert "# Titan Phase 5 Correlation" in (tmp_path / "view.md").read_text()


def test_cli_phase5_stage_reports_failure(tmp_path, capsys):
    args = _cli_args(correlation_db=tmp_path / "correlation.sqlite3", quiet=True)
    # Report without an analysis identifier cannot be correlated.
    assert cli.run_phase5_correlation_stage(args, {"nodes": []}) == 1
    assert "Phase 5 correlation failed" in capsys.readouterr().err
