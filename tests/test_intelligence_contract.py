import json
from pathlib import Path

import pytest

from titan_decoder.core.intelligence import IntelligenceEngine


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas" / "intelligence-report-v1.0.schema.json"
CORPUS_PATH = ROOT / "tests" / "fixtures" / "intelligence" / "calibration-v1.json"


def _load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def test_intelligence_output_matches_v1_schema():
    jsonschema = pytest.importorskip("jsonschema")
    schema = _load_json(SCHEMA_PATH)

    sample = IntelligenceEngine().analyze(
        {
            "nodes": [
                {
                    "id": 1,
                    "depth": 4,
                    "entropy": 7.8,
                    "decode_score": 0.9,
                    "artifact_name": "decoded",
                    "method": "Base64",
                    "content_preview": "powershell https://example.test/a",
                }
            ],
            "iocs": {"urls": ["https://example.test/a"]},
        }
    )

    jsonschema.Draft202012Validator(schema).validate(sample)


def test_intelligence_contract_is_deterministic():
    report = {
        "nodes": [
            {
                "id": 1,
                "depth": 4,
                "entropy": 7.8,
                "decode_score": 0.9,
                "content_preview": "powershell https://example.test/a",
            }
        ],
        "iocs": {"urls": ["https://example.test/a"]},
    }
    engine = IntelligenceEngine()
    assert engine.analyze(report) == engine.analyze(report)


def test_classification_boundaries_are_stable():
    engine = IntelligenceEngine()
    expected = {
        0: "CLEAN",
        15: "CLEAN",
        16: "LOW_RISK_ARTIFACT",
        35: "LOW_RISK_ARTIFACT",
        36: "SUSPICIOUS_OBJECT",
        60: "SUSPICIOUS_OBJECT",
        61: "HIGH_RISK_PAYLOAD",
        80: "HIGH_RISK_PAYLOAD",
        81: "LIKELY_MALICIOUS",
        100: "LIKELY_MALICIOUS",
    }
    for score, label in expected.items():
        assert engine.classify(score) == label


def test_calibration_corpus():
    corpus = _load_json(CORPUS_PATH)
    engine = IntelligenceEngine()

    for case in corpus["cases"]:
        result = engine.analyze(case["report"])
        expected = case["expected"]

        assert result["version"] == corpus["schema_version"], case["id"]
        assert result["intelligence_score"] == expected["score"], case["id"]
        assert result["classification"] == expected["classification"], case["id"]
        assert [item["code"] for item in result["signals"]] == expected["signal_codes"], case["id"]
        assert [item["node_id"] for item in result["top_artifacts"]] == expected["top_node_ids"], case["id"]
