"""Analyst-facing views over Phase 5 correlation results."""

from __future__ import annotations

from html import escape
import json
from typing import Any, Mapping

SCHEMA_VERSION = "analyst-correlation-view-v1.0"


def analyst_summary(result: Mapping[str, Any]) -> dict[str, Any]:
    """Condense a full Phase 5 result into one analyst-oriented view."""

    correlation = result.get("correlation") or {}
    relationships = sorted(
        correlation.get("relationships") or [],
        key=lambda item: (-float(item.get("score", 0.0)), item.get("relationship_id", "")),
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "subject_analysis_id": correlation.get("subject_analysis_id"),
        "relationship_count": len(relationships),
        "top_relationships": relationships[:10],
        "campaigns": result.get("campaigns") or {},
        "timeline_correlation": result.get("timeline_correlation") or {},
        "infrastructure_reuse": result.get("infrastructure_reuse") or {},
        "shared_payloads": result.get("shared_payloads") or {},
        "attribution_hints": result.get("attribution_hints") or {},
    }


def to_markdown(view: Mapping[str, Any]) -> str:
    """Render the analyst view as a short Markdown summary."""

    def count(section: str, key: str) -> Any:
        return (view.get(section) or {}).get(key, 0)

    lines = [
        "# Titan Phase 5 Correlation",
        "",
        f"- Subject: `{view.get('subject_analysis_id') or 'unknown'}`",
        f"- Relationships: **{view.get('relationship_count', 0)}**",
        f"- Campaigns: **{count('campaigns', 'campaign_count')}**",
        f"- Timeline links: **{count('timeline_correlation', 'link_count')}**",
        f"- Infrastructure reuse: **{count('infrastructure_reuse', 'reuse_count')}**",
        f"- Shared payloads: **{count('shared_payloads', 'match_count')}**",
        f"- Attribution hints: **{count('attribution_hints', 'hint_count')}**",
    ]
    disclaimer = (view.get("attribution_hints") or {}).get("disclaimer")
    if disclaimer:
        lines += ["", f"> {disclaimer}"]
    return "\n".join(lines) + "\n"


def to_html(view: Mapping[str, Any]) -> str:
    """Render the analyst view as a self-contained HTML page.

    The full view is embedded as an escaped JSON block so downstream tooling
    can recover the machine-readable data from the HTML artifact.
    """

    return (
        "<!doctype html><html><head><meta charset=\"utf-8\">"
        "<title>Titan Phase 5 Correlation</title></head><body><pre>"
        + escape(to_markdown(view))
        + "</pre><script type=\"application/json\" id=\"correlation-view\">"
        + escape(json.dumps(view, sort_keys=True))
        + "</script></body></html>"
    )
