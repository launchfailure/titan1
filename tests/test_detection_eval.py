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

from tools.eval_detections import evaluate


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


def test_every_rule_has_a_positive_sample():
    # The corpus should exercise each built-in rule at least once, otherwise
    # recall for that rule is untested.
    metrics = evaluate()
    for rule, m in metrics["per_rule"].items():
        assert m["tp"] + m["fn"] >= 1, f"{rule} has no positive sample in the corpus"
