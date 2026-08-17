#!/usr/bin/env python3
"""Measure starter-pack YARA precision and recall on a synthetic corpus."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from tools.yara_corpus_samples import build_yara_corpus  # noqa: E402
from titan_decoder.core.yara_scanner import YaraScanner  # noqa: E402

RULES_DIR = _ROOT / "examples" / "yara_rules"
ALL_RULES = (
    "Titan_PowerShell_Download_Cradle",
    "Titan_Encoded_Command_Invocation",
    "Titan_Executable_In_Decoded_Content",
    "Titan_UPX_Packed_Executable",
    "Titan_JavaScript_Eval_Decode_Chain",
    "Titan_Certutil_Remote_Download",
    "Titan_MSHTA_Remote_Execution",
    "Titan_Regsvr32_Remote_Scriptlet",
)


def _quality(counts: dict[str, int]) -> dict[str, float]:
    tp, fp, fn = counts["tp"], counts["fp"], counts["fn"]
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(f1, 3),
    }


def evaluate(rules_dir: Path = RULES_DIR) -> dict[str, Any]:
    corpus = build_yara_corpus()
    counts = {rule: {"tp": 0, "fp": 0, "fn": 0, "tn": 0} for rule in ALL_RULES}
    samples: list[dict[str, Any]] = []

    for index, sample in enumerate(corpus):
        result = YaraScanner(
            {"enable_yara": True, "yara_rules_dirs": [str(rules_dir)]}
        ).scan([(index, sample.data)])
        if result["state"] != "completed":
            raise RuntimeError(result.get("reason") or "YARA evaluation failed")
        fired = {match["rule"] for match in result["matches"]}
        unexpected = fired - set(ALL_RULES)
        if unexpected:
            raise RuntimeError(
                f"starter pack contains untracked rules: {sorted(unexpected)}"
            )
        for rule in ALL_RULES:
            expected = rule in sample.expected_rules
            matched = rule in fired
            bucket = (
                "tp"
                if expected and matched
                else "fn"
                if expected
                else "fp"
                if matched
                else "tn"
            )
            counts[rule][bucket] += 1
        samples.append(
            {
                "name": sample.name,
                "expected_rules": sorted(sample.expected_rules),
                "fired_rules": sorted(fired),
            }
        )

    return {
        "schema": "titan-yara-quality/1",
        "corpus_size": len(corpus),
        "positive_samples": sum(bool(sample.expected_rules) for sample in corpus),
        "benign_samples": sum(not sample.expected_rules for sample in corpus),
        "per_rule": {
            rule: {**counts[rule], **_quality(counts[rule])} for rule in ALL_RULES
        },
        "per_sample": samples,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", type=Path, help="Write metrics to this JSON file")
    args = parser.parse_args()
    metrics = evaluate()
    rendered = json.dumps(metrics, indent=2) + "\n"
    if args.json:
        args.json.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    weak = {
        rule: values
        for rule, values in metrics["per_rule"].items()
        if values["precision"] < 0.8 or values["recall"] < 0.8
    }
    return 1 if weak else 0


if __name__ == "__main__":
    raise SystemExit(main())
