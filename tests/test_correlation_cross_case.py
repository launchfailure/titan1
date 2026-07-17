"""Tests for cross-case persistence (schema v2) and correlation search.

Covers the Milestone 5 completion work: payload fingerprints and timeline
events persisted in the correlation database (making shared-payload and
timeline correlation fully cross-case, with no ``prior_reports`` needed),
plus indicator search across recorded cases.
"""

import json
import sqlite3

from titan_decoder import cli
from titan_decoder.correlation.database import (
    DATABASE_SCHEMA_VERSION,
    MAX_TIMELINE_EVENTS_PER_ANALYSIS,
    CorrelationDatabase,
)
from titan_decoder.correlation.models import AnalysisRecord
from titan_decoder.correlation.payload_similarity import PayloadFingerprint
from titan_decoder.correlation.service import analyze_milestone5, search_cases
from titan_decoder.correlation.timeline import TimelineEvent


def _report(analysis_id: str, domain: str, timestamp: str):
    return {
        "meta": {"analysis_id": analysis_id, "started_at": "2026-01-01T00:00:00+00:00"},
        "node_count": 2,
        "nodes": [
            {
                "id": 0,
                "parent": None,
                "method": "SOURCE",
                "sha256": f"root-{analysis_id}",
            },
            {
                "id": 1,
                "parent": 0,
                "method": "Base64",
                "decoder_used": "Base64",
                "sha256": "same",
            },
        ],
        "iocs": {"domains": [domain]},
        "evidence": {
            "events": [
                {
                    "event_id": f"ev-{analysis_id}",
                    "event_type": "dns_query",
                    "timestamp": timestamp,
                    "domain": domain,
                }
            ]
        },
    }


def test_fingerprint_round_trip(tmp_path):
    fingerprint = PayloadFingerprint(
        "case-a", "root", payload_hashes=("h1", "h2"), decode_chain=("SOURCE", "Base64")
    )
    with CorrelationDatabase(tmp_path / "c.sqlite3") as database:
        database.record_analysis(AnalysisRecord("case-a", "root"))
        database.record_fingerprint(fingerprint)
        stored = database.iter_fingerprints()
    assert stored == (fingerprint,)
    assert PayloadFingerprint.from_dict(fingerprint.to_dict()) == fingerprint


def test_timeline_event_round_trip_and_cap(tmp_path):
    events = tuple(
        TimelineEvent(
            "case-a",
            f"2026-01-01T00:{index // 60:02d}:{index % 60:02d}Z",
            "dns_query",
            "query",
            source_id=f"src-{index}",
        )
        for index in range(MAX_TIMELINE_EVENTS_PER_ANALYSIS + 5)
    )
    with CorrelationDatabase(tmp_path / "c.sqlite3") as database:
        database.record_analysis(AnalysisRecord("case-a", "root"))
        database.record_timeline_events("case-a", events)
        stored = database.iter_timeline_events()
    assert len(stored) == MAX_TIMELINE_EVENTS_PER_ANALYSIS
    # Recomputed event ids must match the originals after a round trip.
    assert stored[0].event_id == events[0].event_id
    assert TimelineEvent.from_dict(events[0].to_dict()) == events[0]


def test_v1_database_upgrades_on_open(tmp_path):
    path = tmp_path / "old.sqlite3"
    # Minimal v1 layout: analyses/indicators only, no v2 tables.
    connection = sqlite3.connect(str(path))
    connection.executescript(
        """
        CREATE TABLE correlation_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE analyses (
            analysis_id TEXT PRIMARY KEY, root_hash TEXT NOT NULL,
            created_at TEXT, payload_json TEXT NOT NULL
        );
        CREATE TABLE indicators (
            indicator_id TEXT NOT NULL, analysis_id TEXT NOT NULL,
            indicator_type TEXT NOT NULL, normalized_value TEXT NOT NULL,
            payload_json TEXT NOT NULL, PRIMARY KEY (analysis_id, indicator_id)
        );
        INSERT INTO correlation_meta VALUES ('schema_version', '1');
        """
    )
    connection.commit()
    connection.close()

    with CorrelationDatabase(path) as database:
        assert database.schema_version() == DATABASE_SCHEMA_VERSION
        assert database.iter_fingerprints() == ()
        assert database.iter_timeline_events() == ()


def test_shared_payloads_and_timeline_are_cross_case_without_prior_reports(tmp_path):
    """The core Milestone 5 completion: no prior_reports needed."""

    db = tmp_path / "correlation.sqlite3"
    analyze_milestone5(_report("case-a", "c2.test", "2026-01-01T00:00:00Z"), db)
    result = analyze_milestone5(
        _report("case-b", "c2.test", "2026-01-01T00:01:00Z"), db
    )

    assert result["shared_payloads"]["match_count"] == 1
    match = result["shared_payloads"]["matches"][0]
    assert {match["left_analysis_id"], match["right_analysis_id"]} == {
        "case-a",
        "case-b",
    }

    assert result["timeline_correlation"]["event_count"] == 2
    assert result["timeline_correlation"]["link_count"] == 1


def test_prior_reports_still_supported_and_not_double_counted(tmp_path):
    db = tmp_path / "correlation.sqlite3"
    first = _report("case-a", "c2.test", "2026-01-01T00:00:00Z")
    analyze_milestone5(first, db)
    # Passing the recorded report again as prior_reports must not duplicate
    # its fingerprint or events.
    result = analyze_milestone5(
        _report("case-b", "c2.test", "2026-01-01T00:01:00Z"),
        db,
        prior_reports=(first,),
    )
    assert result["shared_payloads"]["match_count"] == 1
    assert result["timeline_correlation"]["event_count"] == 2


def test_search_cases_by_value_and_type(tmp_path):
    db = tmp_path / "correlation.sqlite3"
    analyze_milestone5(_report("case-a", "c2.test", "2026-01-01T00:00:00Z"), db)
    analyze_milestone5(_report("case-b", "c2.test", "2026-01-01T00:01:00Z"), db)
    analyze_milestone5(_report("case-c", "other.test", "2026-01-01T00:02:00Z"), db)

    result = search_cases(db, ["c2.test"])
    assert result["schema_version"] == "correlation-search-v1.0"
    entry = result["results"][0]
    assert entry["analysis_ids"] == ["case-a", "case-b"]
    assert entry["match_count"] == 2
    # Stored indicator payloads carry evidence references.
    assert entry["matches"][0]["indicator"]["references"]

    typed = search_cases(db, ["domains:c2.test", "hashes:c2.test"])
    assert typed["results"][0]["indicator_type"] == "domains"
    assert typed["results"][0]["analysis_ids"] == ["case-a", "case-b"]
    assert typed["results"][1]["analysis_ids"] == []


def test_search_cases_is_case_insensitive_and_handles_urls(tmp_path):
    db = tmp_path / "correlation.sqlite3"
    report = _report("case-a", "c2.test", "2026-01-01T00:00:00Z")
    report["iocs"]["urls"] = ["https://c2.test/gate.php"]
    analyze_milestone5(report, db)

    upper = search_cases(db, ["C2.TEST"])
    assert upper["results"][0]["analysis_ids"] == ["case-a"]

    # A URL query contains colons but must not be parsed as a type filter.
    url = search_cases(db, ["https://c2.test/gate.php"])
    assert url["results"][0]["indicator_type"] is None
    assert url["results"][0]["analysis_ids"] == ["case-a"]


def _cli_args(**over):
    args = cli.build_parser().parse_args([])
    for key, value in over.items():
        setattr(args, key, value)
    return args


def test_cli_correlation_search_mode(tmp_path, capsys):
    from titan_decoder.config import Config

    db = tmp_path / "correlation.sqlite3"
    analyze_milestone5(_report("case-a", "c2.test", "2026-01-01T00:00:00Z"), db)

    args = _cli_args(correlation_search=["c2.test"], correlation_db=db)
    exit_code = cli.handle_info_commands(args, Config())
    assert exit_code == 0
    output = json.loads(capsys.readouterr().out)
    assert output["results"][0]["analysis_ids"] == ["case-a"]


def test_cli_correlation_search_runs_without_input_file(tmp_path, capsys):
    """Search is an early-exit mode: an empty database is a valid query target."""

    from titan_decoder.config import Config

    args = _cli_args(
        correlation_search=["nothing.test"],
        correlation_db=tmp_path / "fresh.sqlite3",
    )
    assert cli.handle_info_commands(args, Config()) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["results"][0]["match_count"] == 0
