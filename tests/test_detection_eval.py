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

from tools.eval_detections import evaluate  # noqa: E402
from tools.corpus_samples import build_corpus  # noqa: E402


def test_detection_eval_separates_classes():
    metrics = evaluate()
    sep = metrics["risk_separation"]
    # Malicious samples must all outscore every benign sample.
    assert sep["separated"], (
        f"risk overlap: benign max {sep['max_benign_score']} "
        f">= malicious min {sep['min_malicious_score']}"
    )


def test_no_rule_precision_or_recall_regression():
    metrics = evaluate()
    weak_precision = {
        rule: values["precision"]
        for rule, values in metrics["per_rule"].items()
        if values["precision"] < 0.8
    }
    weak_recall = {
        rule: values["recall"]
        for rule, values in metrics["per_rule"].items()
        if values["recall"] < 0.8
    }
    assert not weak_precision, f"rules with precision < 0.8: {weak_precision}"
    assert not weak_recall, f"rules with recall < 0.8: {weak_recall}"


def test_every_rule_has_multiple_positive_samples():
    # Multiple distinct positives prevent an exact design fixture from being
    # mistaken for useful recall coverage.
    metrics = evaluate()
    for rule, m in metrics["per_rule"].items():
        assert m["tp"] + m["fn"] >= 2, (
            f"{rule} has fewer than two positive samples in the corpus"
        )


def test_evaluator_discovers_all_builtin_rules():
    from titan_decoder.core.detection_rules import CorrelationRulesEngine

    measured = set(evaluate()["per_rule"])
    builtins = {rule.rule_id for rule in CorrelationRulesEngine().rules}
    assert measured == builtins


def test_detection_corpus_bytes_are_deterministic():
    first = [(sample.name, sample.data) for sample in build_corpus()]
    second = [(sample.name, sample.data) for sample in build_corpus()]
    assert first == second
