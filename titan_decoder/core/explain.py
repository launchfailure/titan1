"""Human-readable rendering for Titan intelligence summaries."""

from __future__ import annotations

from typing import Any, Mapping


def generate_explanation(report: Mapping[str, Any]) -> str:
    intelligence = report.get("intelligence") or {}

    score = int(intelligence.get("intelligence_score") or 0)
    classification = str(intelligence.get("classification") or "UNKNOWN")
    confidence = float(intelligence.get("confidence") or 0.0)
    signals = list(intelligence.get("signals") or [])
    top_artifacts = list(intelligence.get("top_artifacts") or [])
    recommendation = str(
        intelligence.get("recommendation") or "No recommendation is available."
    )

    lines = [
        "Titan Intelligence Report",
        "",
        f"Classification: {classification}",
        f"Score: {score}/100",
        f"Confidence: {confidence:.0%}",
        "",
        "Signals:",
    ]

    if signals:
        for signal in signals:
            summary = signal.get("summary") if isinstance(signal, dict) else str(signal)
            points = signal.get("points") if isinstance(signal, dict) else None
            suffix = f" (+{points})" if isinstance(points, int) else ""
            lines.append(f"- {summary}{suffix}")
    else:
        lines.append("- No suspicious intelligence signals were produced")

    lines.extend(["", "Top artifacts:"])
    if top_artifacts:
        for artifact in top_artifacts:
            node_id = artifact.get("node_id")
            name = artifact.get("artifact_name") or f"node {node_id}"
            reasons = ", ".join(artifact.get("reasons") or [])
            lines.append(
                f"- {name}: {artifact.get('score', 0)}/100"
                + (f" — {reasons}" if reasons else "")
            )
    else:
        lines.append("- No artifacts required prioritization")

    lines.extend(["", "Recommendation:", recommendation])
    return "\n".join(lines)
