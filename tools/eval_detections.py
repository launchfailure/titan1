#!/usr/bin/env python3
"""Evaluate Titan detection rules against the synthetic labeled corpus.

Runs the engine + detection rules over every sample in
``tools/corpus_samples.py`` and reports, per rule, the true/false-positive
counts and precision/recall. It also reports how well the overall risk score
separates the benign from the malicious samples — the signal the 0--100 weights
in ``risk_scoring.py`` are tuned against.

Usage:
    python tools/eval_detections.py [--json PATH]

The measured numbers are what the weight choices in ``risk_scoring.py`` cite.
Re-run after changing rules or weights and refresh ``docs/detection_metrics.json``.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Dict, List

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from tools.corpus_samples import build_corpus  # noqa: E402
from titan_decoder.core.engine import TitanEngine  # noqa: E402
from titan_decoder.config import Config  # noqa: E402
from titan_decoder.core.detection_rules import CorrelationRulesEngine  # noqa: E402
from titan_decoder.core.risk_scoring import RiskScoringEngine  # noqa: E402
from titan_decoder.core.ioc_export import build_ioc_summary  # noqa: E402


MIN_PRECISION = 0.8
MIN_RECALL = 0.8
MIN_POSITIVE_SAMPLES = 2
MIN_NEAR_MISS_SAMPLES = 2


def built_in_rule_ids(
    rules_engine: CorrelationRulesEngine | None = None,
) -> List[str]:
    """Return the live built-in rule set in deterministic order.

    The evaluator deliberately derives this list from the engine. A newly
    shipped ``TITAN-*`` rule therefore fails the corpus-coverage gate until it
    receives labeled positives and adversarial near-misses; it cannot silently
    disappear from the published metrics because somebody forgot to update a
    second hard-coded list.
    """
    engine = rules_engine or CorrelationRulesEngine()
    return sorted(
        rule.rule_id for rule in engine.rules if rule.rule_id.startswith("TITAN-")
    )


def evaluate() -> Dict:
    cfg = Config()
    cfg.set("max_recursion_depth", 8)
    cfg.set("max_node_count", 200)
    engine = TitanEngine(cfg)
    rules_engine = CorrelationRulesEngine()
    risk_engine = RiskScoringEngine()
    all_rules = built_in_rule_ids(rules_engine)
    known_rules = set(all_rules)

    corpus = build_corpus()

    # Per-rule confusion-matrix counts.
    counts = {r: {"tp": 0, "fp": 0, "fn": 0, "tn": 0} for r in all_rules}
    coverage = {
        r: {"positive_samples": 0, "targeted_near_miss_samples": 0} for r in all_rules
    }
    per_sample = []
    benign_scores: List[int] = []
    malicious_scores: List[int] = []
    label_failures: List[str] = []
    near_miss_failures: List[str] = []

    for sample in corpus:
        unknown_expected = sorted(sample.expected_rules - known_rules)
        unknown_near_misses = sorted(sample.near_miss_rules - known_rules)
        overlap = sorted(sample.expected_rules & sample.near_miss_rules)
        if unknown_expected:
            label_failures.append(
                f"{sample.name}: unknown expected rules {unknown_expected}"
            )
        if unknown_near_misses:
            label_failures.append(
                f"{sample.name}: unknown near-miss rules {unknown_near_misses}"
            )
        if overlap:
            label_failures.append(
                f"{sample.name}: rules cannot be positive and near-miss labels {overlap}"
            )
        if sample.malicious and sample.near_miss_rules:
            label_failures.append(
                f"{sample.name}: near-miss labels are only valid on benign samples"
            )

        report = engine.run_analysis(sample.data)
        iocs = build_ioc_summary(report, None)
        detections = rules_engine.evaluate_all(report, iocs)
        fired = {d["rule_id"] for d in detections}
        risk = risk_engine.compute_risk_score(report, iocs, detections)

        for rule in all_rules:
            expected = rule in sample.expected_rules
            got = rule in fired
            if expected:
                coverage[rule]["positive_samples"] += 1
            if rule in sample.near_miss_rules:
                coverage[rule]["targeted_near_miss_samples"] += 1
                if got:
                    near_miss_failures.append(
                        f"{sample.name}: targeted near-miss fired {rule}"
                    )
            if expected and got:
                counts[rule]["tp"] += 1
            elif expected and not got:
                counts[rule]["fn"] += 1
            elif not expected and got:
                counts[rule]["fp"] += 1
            else:
                counts[rule]["tn"] += 1

        if sample.malicious:
            malicious_scores.append(risk["risk_score"])
        else:
            benign_scores.append(risk["risk_score"])

        per_sample.append(
            {
                "name": sample.name,
                "malicious": sample.malicious,
                "expected_rules": sorted(sample.expected_rules),
                "near_miss_rules": sorted(sample.near_miss_rules),
                "fired_rules": sorted(fired),
                "risk_score": risk["risk_score"],
                "risk_level": risk["risk_level"],
            }
        )

    def prf(c: Dict[str, int]) -> Dict[str, float]:
        tp, fp, fn = c["tp"], c["fp"], c["fn"]
        precision = tp / (tp + fp) if (tp + fp) else 1.0
        recall = tp / (tp + fn) if (tp + fn) else 1.0
        f1 = (
            2 * precision * recall / (precision + recall)
            if (precision + recall)
            else 0.0
        )
        return {
            "precision": round(precision, 3),
            "recall": round(recall, 3),
            "f1": round(f1, 3),
        }

    per_rule = {r: {**counts[r], **prf(counts[r]), **coverage[r]} for r in all_rules}

    max_benign = max(benign_scores) if benign_scores else 0
    min_malicious = min(malicious_scores) if malicious_scores else 0

    gate_failures = [*label_failures, *near_miss_failures]
    for rule, metrics in per_rule.items():
        if metrics["precision"] < MIN_PRECISION:
            gate_failures.append(
                f"{rule}: precision {metrics['precision']:.3f} < {MIN_PRECISION:.3f}"
            )
        if metrics["recall"] < MIN_RECALL:
            gate_failures.append(
                f"{rule}: recall {metrics['recall']:.3f} < {MIN_RECALL:.3f}"
            )
        if metrics["positive_samples"] < MIN_POSITIVE_SAMPLES:
            gate_failures.append(
                f"{rule}: {metrics['positive_samples']} positive samples "
                f"< {MIN_POSITIVE_SAMPLES}"
            )
        if metrics["targeted_near_miss_samples"] < MIN_NEAR_MISS_SAMPLES:
            gate_failures.append(
                f"{rule}: {metrics['targeted_near_miss_samples']} targeted "
                f"near-misses < {MIN_NEAR_MISS_SAMPLES}"
            )
    if min_malicious <= max_benign:
        gate_failures.append(
            f"risk overlap: max benign {max_benign} >= min malicious {min_malicious}"
        )

    return {
        "schema_version": "2.0",
        "corpus_size": len(corpus),
        "benign_count": len(benign_scores),
        "malicious_count": len(malicious_scores),
        "per_rule": per_rule,
        "quality_gate": {
            "passed": not gate_failures,
            "minimum_precision": MIN_PRECISION,
            "minimum_recall": MIN_RECALL,
            "minimum_positive_samples_per_rule": MIN_POSITIVE_SAMPLES,
            "minimum_targeted_near_misses_per_rule": MIN_NEAR_MISS_SAMPLES,
            "failures": gate_failures,
        },
        "risk_separation": {
            "max_benign_score": max_benign,
            "min_malicious_score": min_malicious,
            "separated": min_malicious > max_benign,
            "benign_scores": sorted(benign_scores),
            "malicious_scores": sorted(malicious_scores),
        },
        "per_sample": per_sample,
    }


def _print_table(metrics: Dict) -> None:
    print("=" * 72)
    print("Titan detection-rule evaluation (synthetic labeled corpus)")
    print("=" * 72)
    print(
        f"Corpus: {metrics['corpus_size']} samples "
        f"({metrics['malicious_count']} malicious, {metrics['benign_count']} benign)\n"
    )
    print(
        f"{'Rule':<12}{'TP':>4}{'FP':>4}{'FN':>4}{'TN':>4}{'Pos':>5}{'Near':>6}"
        f"{'Prec':>8}{'Recall':>8}{'F1':>7}"
    )
    print("-" * 72)
    for rule, m in metrics["per_rule"].items():
        print(
            f"{rule:<12}{m['tp']:>4}{m['fp']:>4}{m['fn']:>4}{m['tn']:>4}"
            f"{m['positive_samples']:>5}{m['targeted_near_miss_samples']:>6}"
            f"{m['precision']:>8.3f}{m['recall']:>8.3f}{m['f1']:>7.3f}"
        )
    print("-" * 72)
    sep = metrics["risk_separation"]
    print(
        f"\nRisk separation: max benign score = {sep['max_benign_score']}, "
        f"min malicious score = {sep['min_malicious_score']} "
        f"-> {'SEPARATED' if sep['separated'] else 'OVERLAP'}"
    )
    print(f"  benign scores:    {sep['benign_scores']}")
    print(f"  malicious scores: {sep['malicious_scores']}")
    gate = metrics["quality_gate"]
    print(f"\nQuality gate: {'PASSED' if gate['passed'] else 'FAILED'}")
    for failure in gate["failures"]:
        print(f"  - {failure}")


def append_history(metrics: dict, path: str) -> None:
    """Append a per-release summary line to the detection-quality history.

    Keeps a maintained record of precision/recall across releases so users can
    see the engine getting better (or at least not worse), not just different.
    """
    from titan_decoder import __version__

    summary = {
        "version": __version__,
        "schema": "detection-quality/2",
        "corpus_size": metrics["corpus_size"],
        "macro_precision": round(
            sum(m["precision"] for m in metrics["per_rule"].values())
            / len(metrics["per_rule"]),
            3,
        ),
        "macro_recall": round(
            sum(m["recall"] for m in metrics["per_rule"].values())
            / len(metrics["per_rule"]),
            3,
        ),
        "per_rule": {
            r: {
                "precision": m["precision"],
                "recall": m["recall"],
                "positive_samples": m["positive_samples"],
                "targeted_near_miss_samples": m["targeted_near_miss_samples"],
            }
            for r, m in metrics["per_rule"].items()
        },
        "risk_separated": metrics["risk_separation"]["separated"],
        "quality_gate_passed": metrics["quality_gate"]["passed"],
    }
    # De-duplicate by version: replace any existing entry for this version.
    lines = []
    if os.path.exists(path):
        for line in open(path):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            if entry.get("version") != __version__:
                lines.append(line)
    lines.append(json.dumps(summary, sort_keys=True))
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"Appended history entry for v{__version__} to {path}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", type=str, help="Write metrics JSON to this path")
    parser.add_argument(
        "--append-history",
        type=str,
        help="Append a per-release summary line to this history file (JSONL)",
    )
    args = parser.parse_args()

    metrics = evaluate()
    _print_table(metrics)

    if args.json:
        with open(args.json, "w") as f:
            json.dump(metrics, f, indent=2)
        print(f"\nMetrics written to {args.json}")

    if args.append_history:
        append_history(metrics, args.append_history)

    return 0 if metrics["quality_gate"]["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
