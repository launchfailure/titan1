"""Calibration gate for the Threat Intelligence Engine.

Mirrors the Intelligence Layer's calibration corpus
(tests/fixtures/intelligence/calibration-v1.json): every case pins the
exact deterministic output of the engine, so precision regressions —
benign prose producing techniques, LOLBins, or tags — fail CI, and any
intentional rule or confidence change shows up as an explicit diff to
the corpus.
"""

import json
from pathlib import Path

import pytest

from titan_decoder.threat_intel import ThreatIntelligenceEngine

CORPUS_PATH = (
    Path(__file__).resolve().parent
    / "fixtures"
    / "threat_intel"
    / "calibration-v1.json"
)


def _corpus():
    return json.loads(CORPUS_PATH.read_text(encoding="utf-8"))


def _cases():
    return [pytest.param(case, id=case["id"]) for case in _corpus()["cases"]]


@pytest.mark.parametrize("case", _cases())
def test_calibration_case_matches_expected(case):
    result = ThreatIntelligenceEngine().analyze(
        case["report"], detections=case.get("detections")
    )
    expected = case["expected"]

    assert result["confidence"] == expected["confidence"]
    assert [item["technique_id"] for item in result["techniques"]] == expected[
        "technique_ids"
    ]
    assert result["tactics"] == expected["tactics"]
    assert [item["executable"] for item in result["lolbins"]] == expected[
        "lolbin_executables"
    ]
    assert [item["tag"] for item in result["malware_tags"]] == expected["malware_tags"]


@pytest.mark.parametrize("case", _cases())
def test_corpus_kinds_are_internally_consistent(case):
    """Guard the corpus itself: benign cases must expect a completely
    clean assessment, malicious cases must expect at least one finding."""
    expected = case["expected"]
    if case["kind"] == "benign":
        assert expected["confidence"] == 0.0
        assert expected["technique_ids"] == []
        assert expected["lolbin_executables"] == []
        assert expected["malware_tags"] == []
    else:
        assert case["kind"] == "malicious"
        assert expected["confidence"] > 0.0
        assert (
            expected["technique_ids"]
            or expected["lolbin_executables"]
            or expected["malware_tags"]
        )


def test_corpus_covers_benign_and_malicious():
    kinds = {case["kind"] for case in _corpus()["cases"]}
    assert kinds == {"benign", "malicious"}
