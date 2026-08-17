"""CI quality gate for the shipped starter YARA pack."""

import pytest

pytest.importorskip("yara")

from tools.eval_yara import ALL_RULES, evaluate  # noqa: E402


def test_every_starter_rule_has_multiple_positive_samples():
    metrics = evaluate()
    assert set(metrics["per_rule"]) == set(ALL_RULES)
    assert all(
        values["tp"] + values["fn"] >= 2 for values in metrics["per_rule"].values()
    )


def test_starter_yara_precision_and_recall_gate():
    metrics = evaluate()
    weak = {
        rule: values
        for rule, values in metrics["per_rule"].items()
        if values["precision"] < 0.8 or values["recall"] < 0.8
    }
    assert not weak, f"starter YARA quality regression: {weak}"
