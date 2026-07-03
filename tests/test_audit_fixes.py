"""Regression tests for the 2026-07 repository audit fixes.

Each test pins one previously-broken behavior; see CHANGELOG "Unreleased".
"""

import json
import zlib

from titan_decoder.core.device_forensics import ForensicsEngine
from titan_decoder.core.evidence_links import top_links
from titan_decoder.core.evidence_models import EvidenceEvent, parse_timestamp
from titan_decoder.core.ioc_export import (
    build_ioc_summary,
    export_misp,
    export_stix_minimal,
)
from titan_decoder.core.correlation import CorrelationStore
from titan_decoder.core.scoring import PruningEngine, ScoringEngine
from titan_decoder.decoders.base import PDFDecoder, UnicodeEscapeDecoder


def test_imsi_detection_not_dead_and_imei_luhn_validated():
    # 490154203237518 is Luhn-valid (IMEI); 310150123456789 is not (IMSI).
    text = "IMEI 490154203237518 IMSI 310150123456789"
    summary = ForensicsEngine().analyze(
        {"nodes": [{"id": 0, "parent": None, "content_preview": text, "content_type": "Text"}]}
    )
    assert summary["mobile_ids"]["imei"] == ["490154203237518"]
    assert summary["mobile_ids"]["imsi"] == ["310150123456789"]


def test_ioc_summary_includes_binary_nodes():
    # Must match engine behavior: C2 indicators in Binary-classified nodes
    # were dropped from detections/exports by the Text-only filter.
    report = {
        "nodes": [
            {"content_preview": "http://binary-c2.example.net/x", "content_type": "Binary"}
        ]
    }
    assert build_ioc_summary(report)["urls"] == ["http://binary-c2.example.net/x"]


def test_top_links_ranks_high_confidence_first():
    links = [
        {
            "src": {"type": "a", "value": "1"},
            "dst": {"type": "b", "value": "2"},
            "confidence": "medium",
            "reason_code": "r",
            "sources": [{}],
        },
        {
            "src": {"type": "a", "value": "1"},
            "dst": {"type": "b", "value": "3"},
            "confidence": "high",
            "reason_code": "r",
            "sources": [{}],
        },
    ]
    assert top_links(links, 1)[0]["confidence"] == "high"


def test_hash_exports_label_by_digest_length(tmp_path):
    iocs = {"hashes": ["d" * 32, "e" * 40, "f" * 64]}

    stix_path = tmp_path / "iocs.stix.json"
    export_stix_minimal(iocs, stix_path)
    patterns = [o["pattern"] for o in json.loads(stix_path.read_text())["objects"]]
    assert any("'MD5'" in p for p in patterns)
    assert any("'SHA-1'" in p for p in patterns)
    assert any("'SHA-256'" in p for p in patterns)
    assert not any("'SHA-256'" in p and "d" * 32 in p for p in patterns)

    misp_path = tmp_path / "iocs.misp.json"
    export_misp(iocs, misp_path)
    types = sorted(
        a["type"] for a in json.loads(misp_path.read_text())["Event"]["Attribute"]
    )
    assert types == ["md5", "sha1", "sha256"]


def test_unicode_escape_surrogate_pairs():
    decoder = UnicodeEscapeDecoder()
    data = b"payload \\ud83d\\ude00 http://evil.example/x \\ud800 lone"
    out, ok = decoder.decode(data)
    assert ok
    assert "😀".encode("utf-8") in out  # pair combined
    assert b"http://evil.example/x" in out  # rest of payload survives
    assert b"\\ud800" in out  # lone surrogate stays literal


def test_pdf_decoder_handles_nested_dictionaries():
    payload = b"http://c2.example.com/gate"
    pdf = (
        b"%PDF-1.4\n1 0 obj\n"
        b"<< /Filter /FlateDecode /DecodeParms << /Predictor 1 >> /Length 99 >>\n"
        b"stream\n" + zlib.compress(payload) + b"\nendstream\nendobj\n%%EOF"
    )
    out, ok = PDFDecoder().decode(pdf)
    assert ok
    assert payload in out


def test_parse_timestamp_millisecond_epochs():
    assert parse_timestamp("1720000000") == parse_timestamp("1720000000000")
    assert parse_timestamp(1720000000000) == parse_timestamp(1720000000)
    ts = parse_timestamp("1720000000000")
    assert ts is not None and ts.startswith("2024-")


def test_evidence_event_ids_unique():
    a = EvidenceEvent(event_type="x", timestamp=None, source="s", extracted_by="e")
    b = EvidenceEvent(event_type="x", timestamp=None, source="s", extracted_by="e")
    assert a.event_id != b.event_id


def test_pruning_default_threshold_matches_config_default():
    # Config.DEFAULT_CONFIG uses 0.01; a 0.1 fallback here silently changed
    # pruning for direct constructor use.
    assert PruningEngine({}).min_score_threshold == 0.01


def test_xml_structure_pattern_requires_declaration():
    # rb"<?xml" made '<' optional and matched bare "xml" anywhere.
    score_with_xml_word = ScoringEngine._structural_emergence_score(
        b"the xml word alone"
    )
    score_with_decl = ScoringEngine._structural_emergence_score(
        b"<?xml version='1.0'?><a/>"
    )
    assert score_with_decl > score_with_xml_word


def test_correlation_store_does_not_duplicate_indicators(tmp_path):
    db = tmp_path / "corr.db"
    iocs = {"urls": ["http://x.example/a"]}
    with CorrelationStore(db) as store:
        store.record_analysis("run-1", iocs)
        store.record_analysis("run-1", iocs)  # same run recorded twice
        store.record_analysis("run-2", iocs)
        cur = store.conn.cursor()
        cur.execute("SELECT COUNT(*) FROM indicators")
        assert cur.fetchone()[0] == 1
        cur.execute("SELECT COUNT(*) FROM analysis_links")
        assert cur.fetchone()[0] == 2  # one link per distinct run
