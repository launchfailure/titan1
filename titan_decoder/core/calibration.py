"""Labeled decoder/analyzer calibration and quality metrics."""

from __future__ import annotations

import base64
from hashlib import sha256
import json
from pathlib import Path
from typing import Any, Mapping

from ..config import Config
from .engine import TitanEngine


def _ratio(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 6) if denominator else 0.0


def _metrics(counts: Mapping[str, int]) -> dict[str, Any]:
    tp = int(counts.get("true_positive", 0))
    tn = int(counts.get("true_negative", 0))
    fp = int(counts.get("false_positive", 0))
    fn = int(counts.get("false_negative", 0))
    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    return {
        **dict(counts),
        "precision": precision,
        "recall": recall,
        "f1": _ratio(2 * tp, 2 * tp + fp + fn),
        "specificity": _ratio(tn, tn + fp),
        "accuracy": _ratio(tp + tn, tp + tn + fp + fn),
    }


class CalibrationRunner:
    """Evaluate labeled cases against specific registered components."""

    def __init__(self, config: Config | None = None):
        self.config = config or Config()

    def run(self, corpus_path: Path) -> dict[str, Any]:
        corpus_path = corpus_path.expanduser().resolve()
        value = json.loads(corpus_path.read_text(encoding="utf-8"))
        if not isinstance(value, dict) or value.get("schema_version") != "1.0":
            raise ValueError("calibration corpus must use schema_version 1.0")
        cases = value.get("cases")
        if not isinstance(cases, list):
            raise ValueError("calibration corpus cases must be a list")
        engine = TitanEngine(self.config)
        components: dict[str, dict[str, Any]] = {
            "decoder": {str(item.name): item for item in engine.decoders},
            "analyzer": {str(item.name): item for item in engine.analyzers},
        }
        details: list[dict[str, Any]] = []
        counts: dict[str, dict[str, int]] = {}
        skipped: list[dict[str, str]] = []
        for raw_case in cases:
            if not isinstance(raw_case, dict):
                continue
            case_id = str(raw_case.get("id") or f"case-{len(details) + 1}")
            kind = str(raw_case.get("kind") or "")
            component_name = str(raw_case.get("component") or "")
            component = components.get(kind, {}).get(component_name)
            if component is None:
                skipped.append(
                    {
                        "id": case_id,
                        "reason": f"{kind} component is unavailable: {component_name}",
                    }
                )
                continue
            try:
                data = self._case_data(raw_case, corpus_path.parent)
                expected = bool(raw_case.get("expected_match"))
                predicted, observation = self._evaluate(kind, component, data, raw_case)
            except Exception as exc:
                expected = bool(raw_case.get("expected_match"))
                predicted = False
                observation = {"error": f"{type(exc).__name__}: {exc}"}
            key = f"{kind}:{component_name}"
            component_counts = counts.setdefault(
                key,
                {
                    "true_positive": 0,
                    "true_negative": 0,
                    "false_positive": 0,
                    "false_negative": 0,
                },
            )
            outcome = (
                "true_positive"
                if expected and predicted
                else "false_negative"
                if expected
                else "false_positive"
                if predicted
                else "true_negative"
            )
            component_counts[outcome] += 1
            details.append(
                {
                    "id": case_id,
                    "kind": kind,
                    "component": component_name,
                    "expected_match": expected,
                    "predicted_match": predicted,
                    "outcome": outcome,
                    **observation,
                }
            )

        by_component = {key: _metrics(item) for key, item in sorted(counts.items())}
        aggregate_counts = {
            label: sum(item[label] for item in counts.values())
            for label in (
                "true_positive",
                "true_negative",
                "false_positive",
                "false_negative",
            )
        }
        aggregate = _metrics(aggregate_counts)
        min_precision = float(self.config.get("calibration_min_precision", 0.90))
        min_recall = float(self.config.get("calibration_min_recall", 0.90))
        failures = [
            {
                "component": key,
                "precision": item["precision"],
                "recall": item["recall"],
            }
            for key, item in by_component.items()
            if item["precision"] < min_precision or item["recall"] < min_recall
        ]
        return {
            "schema_version": "1.0",
            "corpus": str(corpus_path),
            "corpus_name": str(value.get("name") or corpus_path.stem),
            "case_count": len(details),
            "skipped_count": len(skipped),
            "aggregate": aggregate,
            "components": by_component,
            "quality_gate": {
                "passed": not failures and bool(details),
                "minimum_precision": min_precision,
                "minimum_recall": min_recall,
                "failures": failures,
            },
            "cases": details,
            "skipped": skipped,
        }

    @staticmethod
    def _case_data(value: Mapping[str, Any], root: Path) -> bytes:
        if "data_base64_parts" in value:
            parts = value["data_base64_parts"]
            if (
                not isinstance(parts, list)
                or not parts
                or not all(isinstance(part, str) for part in parts)
            ):
                raise ValueError("data_base64_parts must be a non-empty string list")
            conflicting = {
                key for key in ("data_text", "data_hex", "fixture") if key in value
            }
            if conflicting:
                raise ValueError("case must declare exactly one data representation")
            return base64.b64decode("".join(parts), validate=True)
        representations = [
            key
            for key in ("data_text", "data_base64", "data_hex", "fixture")
            if key in value
        ]
        if len(representations) != 1:
            raise ValueError("case must declare exactly one data representation")
        key = representations[0]
        if key == "data_text":
            return str(value[key]).encode("utf-8")
        if key == "data_base64":
            return base64.b64decode(str(value[key]), validate=True)
        if key == "data_hex":
            return bytes.fromhex(str(value[key]))
        path = (root / str(value[key])).resolve()
        if root not in path.parents and path != root:
            raise ValueError("fixture path escapes the calibration directory")
        return path.read_bytes()

    @staticmethod
    def _evaluate(
        kind: str,
        component: Any,
        data: bytes,
        case: Mapping[str, Any],
    ) -> tuple[bool, dict[str, Any]]:
        if kind == "decoder":
            can_process = bool(component.can_decode(data))
            decoded = data
            success = False
            if can_process:
                decoded, success = component.decode(data)
            predicted = bool(can_process and success and decoded != data)
            expected_hash = str(case.get("expected_output_sha256") or "")
            output_hash = sha256(decoded).hexdigest() if predicted else None
            if expected_hash and output_hash != expected_hash:
                predicted = False
            return predicted, {
                "can_process": can_process,
                "output_sha256": output_hash,
            }
        if kind == "analyzer":
            can_process = bool(component.can_analyze(data))
            artifacts = list(component.analyze(data)) if can_process else []
            names = sorted(str(name) for name, _ in artifacts)
            expected_names = {
                str(value) for value in case.get("expected_artifacts") or ()
            }
            predicted = bool(can_process and artifacts)
            if expected_names and not expected_names.issubset(names):
                predicted = False
            return predicted, {"can_process": can_process, "artifacts": names}
        raise ValueError(f"unsupported calibration kind: {kind}")
