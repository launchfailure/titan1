"""ATT&CK technique metadata on detection rules.

Built-in rules carry static `attack_ids`; triggered detections expose them so
the Threat Intelligence Engine can use detections as corroborating technique
evidence. The catalog-membership test keeps the rule metadata and the bundled
ATT&CK subset from drifting apart.
"""

import json
from pathlib import Path

from titan_decoder.core.detection_rules import CorrelationRulesEngine
from titan_decoder.threat_intel import ThreatIntelligenceEngine
from titan_decoder.threat_intel.catalog import load_attack_catalog


def test_every_builtin_rule_has_attack_ids():
    engine = CorrelationRulesEngine()
    builtin = [r for r in engine.rules if not hasattr(r, "source")]
    assert builtin, "no built-in rules loaded"
    for rule in builtin:
        assert rule.attack_ids, f"{rule.rule_id} has no attack_ids"


def test_builtin_attack_ids_exist_in_catalog():
    by_id = load_attack_catalog()["by_id"]
    engine = CorrelationRulesEngine()
    for rule in engine.rules:
        for technique_id in rule.attack_ids:
            assert technique_id in by_id, (
                f"{rule.rule_id} references {technique_id}, which is missing "
                "from titan_decoder/threat_intel/data/attack_catalog.json"
            )


def test_triggered_detection_includes_attack_ids():
    report = {
        "nodes": [
            {"depth": 0, "decoder_used": "Base64"},
            {"depth": 1, "decoder_used": "Base64"},
            {"depth": 2, "decoder_used": "Base64"},
            {"depth": 3, "decoder_used": "Base64"},
        ]
    }
    detections = CorrelationRulesEngine().evaluate_all(report, {})
    deep_b64 = next(d for d in detections if d["rule_id"] == "TITAN-001")
    assert deep_b64["attack_ids"] == ["T1027"]


def test_pack_rule_attack_ids_flow_to_detections(tmp_path: Path):
    pack = {
        "schema_version": 1,
        "pack": {"name": "Fixture Pack", "version": "0.1.0"},
        "rules": [
            {
                "id": "FIX-001",
                "name": "Contains marker",
                "description": "fixture",
                "severity": "low",
                "type": "content_regex",
                "pattern": "marker",
                "attack_ids": ["T1027"],
            }
        ],
    }
    path = tmp_path / "pack.json"
    path.write_text(json.dumps(pack))

    report = {"nodes": [{"id": 0, "content_preview": "the marker string"}]}
    detections = CorrelationRulesEngine([path]).evaluate_all(report, {})
    fired = next(d for d in detections if d["rule_id"] == "FIX-001")
    assert fired["attack_ids"] == ["T1027"]


def test_detection_attack_ids_reach_threat_intelligence():
    """End-to-end: a fired built-in rule corroborates technique findings."""
    report = {
        "nodes": [
            {"id": 0, "depth": 0, "decoder_used": "Base64", "content_preview": ""},
            {"id": 1, "depth": 1, "decoder_used": "Base64", "content_preview": ""},
            {"id": 2, "depth": 2, "decoder_used": "Base64", "content_preview": ""},
            {"id": 3, "depth": 3, "decoder_used": "Base64", "content_preview": ""},
        ]
    }
    detections = CorrelationRulesEngine().evaluate_all(report, {})
    assert any(d["rule_id"] == "TITAN-001" for d in detections)

    result = ThreatIntelligenceEngine().analyze(report, detections=detections)
    t1027 = next(
        item for item in result["techniques"] if item["technique_id"] == "T1027"
    )
    assert "detection-metadata" in t1027["source_rules"]
    assert any(ev.get("kind") == "detection" for ev in t1027["evidence"])
