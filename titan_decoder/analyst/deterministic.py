"""Deterministic, citation-carrying answers built purely from the ledger.

This is both the no-model default and the fallback when a model answer
fails validation or the backend errors: the analyst always has something
grounded to say, and every factual line carries its citation.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Iterable

from .evidence import EvidenceItem
from .questions import QuestionPlan

MAX_ANSWER_LINES = 60


def _line(item: EvidenceItem) -> str:
    value = item.value
    if isinstance(value, dict):
        summary = value.get("summary") or value.get("name") or value.get("description")
        if summary:
            value = summary
        else:
            value = ", ".join(f"{k}={v}" for k, v in list(value.items())[:5])
    return f"- {item.title}: {value} {item.citation()}"


def deterministic_answer(plan: QuestionPlan, items: Iterable[EvidenceItem]) -> str:
    items = list(items)
    if not items:
        return "Titan did not record evidence that answers this question."

    groups: dict[str, list[EvidenceItem]] = defaultdict(list)
    for item in items:
        groups[item.kind].append(item)

    lines: list[str] = []
    if plan.intent == "explain_risk":
        lines.append("Titan's recorded risk is supported by:")
        for kind in ("risk", "intelligence", "signal", "detection"):
            lines.extend(_line(x) for x in groups[kind][:8])
    elif plan.intent == "powershell_stages":
        lines.append("Decoded PowerShell-related stages:")
        lines.extend(_line(x) for x in items if x.kind == "node")
        if len(lines) == 1:
            return "Titan did not record a PowerShell-related decoded stage."
    elif plan.intent == "decode_chain":
        nodes = sorted(
            groups["node"],
            key=lambda x: (
                int(x.value.get("depth", 0)) if isinstance(x.value, dict) else 0,
                x.path,
            ),
        )
        lines.append("Decoding chain:")
        for node in nodes:
            value = node.value if isinstance(node.value, dict) else {}
            parent = (
                value.get("parent")
                if value.get("parent") is not None
                else value.get("parent_id")
            )
            method = (
                value.get("method")
                or value.get("decoder_used")
                or value.get("transformation")
                or node.title
            )
            suffix = f" from node {parent}" if parent is not None else ""
            lines.append(
                f"- depth {value.get('depth', 0)}: {method}{suffix} {node.citation()}"
            )
    elif plan.intent == "ioc_detection":
        lines.append("Relevant indicators and detections:")
        for kind in ("ioc", "detection", "signal"):
            lines.extend(_line(x) for x in groups[kind][:12])
    elif plan.intent == "mitre":
        lines.append("MITRE ATT&CK techniques recorded by Titan:")
        lines.extend(_line(x) for x in groups["attack"])
        if not groups["attack"]:
            lines.extend(_line(x) for x in groups["detection"][:10])
    elif plan.intent == "compare":
        lines.append("Cross-case evidence:")
        for kind in ("relationship", "attribution_hint", "ioc", "attack", "node"):
            lines.extend(_line(x) for x in groups[kind][:10])
    elif plan.intent == "next_steps":
        lines.append("Evidence-backed next steps:")
        for item in groups["intelligence"]:
            if "recommend" in item.title.lower():
                lines.append(_line(item))
        if len(lines) == 1:
            lines.append(
                "- Review the cited detections, IOCs, and top artifacts before containment."
            )
            for kind in ("detection", "ioc", "node"):
                lines.extend(_line(x) for x in groups[kind][:4])
    else:
        lines.append("Investigation summary:")
        for kind in ("risk", "intelligence", "signal", "detection", "ioc", "attack"):
            lines.extend(_line(x) for x in groups[kind][:8])
    return "\n".join(lines[:MAX_ANSWER_LINES])
