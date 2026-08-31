"""Guard the detection-rule quality measured by tools/eval_detections.py.

This keeps the labeled-corpus evaluation honest in CI: it asserts that the
overall risk score still separates the benign from the malicious samples and
that no built-in rule's precision regresses. If a rule or weight change breaks
that separation, this test fails.
"""

import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from tools.eval_detections import (  # noqa: E402
    MIN_NEAR_MISS_SAMPLES,
    MIN_POSITIVE_SAMPLES,
    built_in_rule_ids,
    evaluate,
)
from tools.corpus_samples import Sample  # noqa: E402
import tools.eval_detections as detection_eval  # noqa: E402


def test_detection_eval_separates_classes():
    metrics = evaluate()
    sep = metrics["risk_separation"]
    # Malicious samples must all outscore every benign sample.
    assert sep["separated"], (
        f"risk overlap: benign max {sep['max_benign_score']} "
        f">= malicious min {sep['min_malicious_score']}"
    )


def test_no_rule_precision_regression():
    metrics = evaluate()
    weak = {
        rule: m["precision"]
        for rule, m in metrics["per_rule"].items()
        if m["precision"] < 0.8
    }
    assert not weak, f"rules with precision < 0.8: {weak}"


def test_detection_quality_gate_passes():
    metrics = evaluate()
    assert metrics["quality_gate"]["passed"], metrics["quality_gate"]["failures"]


def test_quality_metrics_cover_the_live_builtin_rule_set():
    metrics = evaluate()
    assert set(metrics["per_rule"]) == set(built_in_rule_ids())


def test_every_rule_has_positive_and_targeted_near_miss_depth():
    # Generic true negatives are not enough. Each rule needs multiple labeled
    # positives and benign cases deliberately placed near its trigger boundary.
    metrics = evaluate()
    for rule, m in metrics["per_rule"].items():
        assert m["positive_samples"] >= MIN_POSITIVE_SAMPLES, (
            f"{rule} has only {m['positive_samples']} positive samples"
        )
        assert m["targeted_near_miss_samples"] >= MIN_NEAR_MISS_SAMPLES, (
            f"{rule} has only {m['targeted_near_miss_samples']} targeted near-misses"
        )


def test_corpus_integrity_rejects_duplicate_payloads(monkeypatch):
    samples = [
        Sample("first", b"same payload", malicious=False),
        Sample("second", b"same payload", malicious=False),
    ]
    monkeypatch.setattr(detection_eval, "build_corpus", lambda: samples)

    failures = detection_eval.evaluate()["quality_gate"]["failures"]
    assert any("duplicate payload also used by first" in item for item in failures)


def test_near_miss_required_decoder_must_be_observed(monkeypatch):
    samples = [
        Sample(
            "weak_xor_near_miss",
            b"ordinary undecoded text",
            malicious=False,
            near_miss_rules={"TITAN-006"},
            required_decoders={"XOR"},
        )
    ]
    monkeypatch.setattr(detection_eval, "build_corpus", lambda: samples)

    failures = detection_eval.evaluate()["quality_gate"]["failures"]
    assert any("required decoders not observed ['XOR']" in item for item in failures)
