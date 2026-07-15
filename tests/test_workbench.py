"""Unit tests for the Analyst Workbench: models, workspace, search, exports."""

import json
import zipfile
from pathlib import Path

import pytest

from titan_decoder.workbench.export import (
    export_case_bundle,
    export_graph,
    export_iocs_csv,
    export_timeline_csv,
)
from titan_decoder.workbench.models import TitanReport
from titan_decoder.workbench.render import (
    correlation_view,
    decode_tree,
    detection_view,
    evidence_view,
    indicator_view,
    node_detail,
    report_overview,
    timeline_view,
)
from titan_decoder.workbench.search import search_reports
from titan_decoder.workbench.workspace import InvestigationWorkspace


def sample_report():
    return {
        "meta": {"analysis_id": "case-a"},
        "node_count": 2,
        "nodes": [
            {
                "id": 0,
                "parent": None,
                "depth": 0,
                "method": "SOURCE",
                "content_type": "Text",
                "sha256": "root-hash",
                "content_preview": "aGk=",
            },
            {
                "id": 1,
                "parent": 0,
                "depth": 1,
                "method": "DECODE_Base64",
                "decoder_used": "Base64",
                "content_type": "Text",
                "sha256": "child-hash",
                "content_preview": "hi malware-marker",
            },
        ],
        "iocs": {"domains": ["c2.test"], "urls": ["http://c2.test/gate"]},
        "detections": [
            {"rule_id": "X-1", "severity": "high", "name": "Hit", "attack_ids": ["T1027"]}
        ],
        "risk_assessment": {"risk_level": "HIGH", "risk_score": 80},
        "intelligence": {"classification": "suspicious"},
        "evidence": {
            "events": [
                {"timestamp": "2026-01-01T00:00:00Z", "event_type": "dns_query", "domain": "c2.test"}
            ],
            "indicators": [{"indicator_type": "domain", "value": "c2.test"}],
            "top_pivots": ["domain:c2.test"],
            "top_links": [],
        },
        "correlation": {
            "relationships": [
                {"left_analysis_id": "case-a", "right_analysis_id": "case-b", "score": 0.8, "confidence": "high"}
            ]
        },
        "attribution_hints": {
            "hints": [
                {"left_analysis_id": "case-a", "right_analysis_id": "case-b", "confidence": "medium", "score": 0.5}
            ]
        },
        "campaigns": {"campaign_count": 1, "campaigns": [
            {"confidence": "high", "member_analysis_ids": ["case-a", "case-b"]}
        ]},
    }


def _load(tmp_path, name="report.json", data=None):
    path = tmp_path / name
    path.write_text(json.dumps(data if data is not None else sample_report()))
    return TitanReport.load(path)


def test_report_summary_from_engine_shape(tmp_path):
    report = _load(tmp_path)
    s = report.summary
    assert s.analysis_id == "case-a"
    assert s.root_hash == "root-hash"  # from the parent-None node
    assert s.node_count == 2
    assert s.ioc_count == 2
    assert s.detection_count == 1
    assert s.risk_level == "HIGH" and s.risk_score == 80.0
    assert s.classification == "suspicious"
    assert s.relationship_count == 1 and s.campaign_count == 1


def test_report_load_rejects_non_object(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("[1, 2, 3]")
    with pytest.raises(ValueError):
        TitanReport.load(path)


def test_node_navigation(tmp_path):
    report = _load(tmp_path)
    root = report.node_by_id(0)
    assert root is not None and root["parent"] is None
    children = report.children_of(0)
    assert [c["id"] for c in children] == [1]


def test_render_views(tmp_path):
    report = _load(tmp_path)
    assert "case-a" in report_overview(report)
    tree = decode_tree(report)
    assert "SOURCE" in tree and "DECODE_Base64" in tree
    assert decode_tree(report, filter_text="base64") .count("•") == 1
    assert "c2.test" in indicator_view(report)
    assert indicator_view(report, filter_text="urls").count("http") == 1
    assert "X-1" in detection_view(report) and "T1027" in detection_view(report)
    assert "dns_query" in timeline_view(report)
    assert "No matching timeline events." in timeline_view(report, filter_text="nope")
    evidence = evidence_view(report)
    assert "domain             c2.test" in evidence and "Top pivots" in evidence
    correlation = correlation_view(report)
    assert "case-a ↔ case-b" in correlation and "campaign [high]" in correlation


def test_node_detail_shows_lineage(tmp_path):
    report = _load(tmp_path)
    detail = node_detail(report, 1)
    assert "Parent            0" in detail
    assert "Base64" in detail
    assert "No node with id 42." in node_detail(report, 42)


def test_search_ranks_exact_above_substring(tmp_path):
    report = _load(tmp_path)
    hits = search_reports([report], "c2.test")
    assert hits
    assert hits[0].score == 100  # exact indicator value ranks first
    assert any("iocs" in hit.location for hit in hits)
    assert search_reports([report], "") == []


def test_workspace_roundtrip_and_tolerant_load(tmp_path):
    workspace = InvestigationWorkspace("Case A")
    report_path = tmp_path / "r.json"
    report_path.write_text("{}")
    workspace.add_report(report_path)
    workspace.tag(report_path, "priority")
    workspace.set_note(report_path, "review")
    workspace.set_status(report_path, "in-progress")
    workspace.notes.append("shared infra suspected")
    out = tmp_path / "workspace.json"
    workspace.save(out)

    loaded = InvestigationWorkspace.load(out)
    assert loaded.name == "Case A"
    entry = loaded.entries[0]
    assert entry.tags == ["priority"]
    assert entry.note == "review"
    assert entry.status == "in-progress"
    assert loaded.notes == ["shared infra suspected"]

    # Unknown keys (newer schema) must not crash the load.
    data = json.loads(out.read_text())
    data["entries"][0]["future_field"] = True
    out.write_text(json.dumps(data))
    assert InvestigationWorkspace.load(out).entries[0].tags == ["priority"]

    with pytest.raises(ValueError):
        workspace.set_status(report_path, "abandoned")


def test_workspace_matches_json_schema(tmp_path):
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(
        (
            Path(__file__).resolve().parents[1]
            / "schemas"
            / "analyst-workspace-v1.0.schema.json"
        ).read_text()
    )
    workspace = InvestigationWorkspace("Case A")
    workspace.add_report(tmp_path / "r.json")
    workspace.tag(tmp_path / "r.json", "priority")
    jsonschema.validate(workspace.to_dict(), schema)


def test_exports(tmp_path):
    report = _load(tmp_path)

    ioc_csv = tmp_path / "iocs.csv"
    export_iocs_csv([report], ioc_csv)
    text = ioc_csv.read_text()
    assert "c2.test" in text and "case-a" in text

    timeline_csv = tmp_path / "timeline.csv"
    export_timeline_csv([report], timeline_csv)
    assert "dns_query" in timeline_csv.read_text()

    mermaid = tmp_path / "graph.mmd"
    export_graph(report, mermaid, "mermaid")
    assert "flowchart" in mermaid.read_text() or "graph" in mermaid.read_text()
    with pytest.raises(ValueError):
        export_graph(report, tmp_path / "x", "png")

    workspace = InvestigationWorkspace("Case A")
    workspace.add_report(report.path)
    bundle = tmp_path / "case.zip"
    export_case_bundle(workspace, [report], bundle)
    with zipfile.ZipFile(bundle) as archive:
        names = archive.namelist()
        assert "workspace.json" in names and "manifest.json" in names
        assert any(name.startswith("reports/") for name in names)
        manifest = json.loads(archive.read("manifest.json"))
        assert manifest["report_count"] == 1
        assert manifest["reports"][0]["analysis_id"] == "case-a"
