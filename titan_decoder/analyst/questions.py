"""Deterministic question routing.

Maps an analyst's natural-language question to an intent, the evidence
kinds worth retrieving, and search terms. Routing is rule-based on purpose:
the *model* never decides what evidence it gets to see.
"""

from __future__ import annotations

from dataclasses import dataclass
import re


@dataclass(frozen=True)
class QuestionPlan:
    intent: str
    kinds: tuple[str, ...]
    terms: tuple[str, ...]
    comparison: bool = False


def plan_question(question: str) -> QuestionPlan:
    lower = question.lower().strip()
    words = tuple(sorted(set(re.findall(r"[a-zA-Z0-9_.:-]{3,}", lower))))

    if "why" in lower and ("risk" in lower or "high" in lower):
        return QuestionPlan(
            "explain_risk", ("risk", "intelligence", "signal", "detection"), words
        )
    if "powershell" in lower or "pwsh" in lower:
        return QuestionPlan(
            "powershell_stages",
            ("node", "detection", "attack"),
            ("powershell", "pwsh", "encodedcommand"),
        )
    if "decoding chain" in lower or "decode chain" in lower or "decoding" in lower:
        return QuestionPlan("decode_chain", ("node",), words)
    if "ioc" in lower and (
        "detection" in lower or "caused" in lower or "trigger" in lower
    ):
        return QuestionPlan("ioc_detection", ("ioc", "detection", "signal"), words)
    if "mitre" in lower or ("attack" in lower and "technique" in lower):
        return QuestionPlan("mitre", ("attack", "detection", "signal"), words)
    if "summar" in lower or "overview" in lower:
        return QuestionPlan(
            "summary",
            ("risk", "intelligence", "signal", "detection", "ioc", "attack", "node"),
            words,
        )
    if "compare" in lower or "previous case" in lower or "other case" in lower:
        return QuestionPlan(
            "compare",
            ("relationship", "attribution_hint", "ioc", "node", "attack"),
            words,
            comparison=True,
        )
    if "next step" in lower or "recommend" in lower:
        return QuestionPlan(
            "next_steps",
            ("intelligence", "signal", "detection", "ioc", "attack"),
            words,
        )
    return QuestionPlan("general", (), words)
