"""Read-only text views over loaded reports.

Every view accepts an optional case-insensitive ``filter_text`` and renders
plain text — the app decides how to display it.
"""

from __future__ import annotations

from typing import Any

from .models import TitanReport


def report_overview(report: TitanReport) -> str:
    s = report.summary
    return "\n".join(
        [
            f"Analysis ID       {s.analysis_id}",
            f"Root hash         {s.root_hash or 'unknown'}",
            f"Classification    {s.classification}",
            f"Risk              {s.risk_level} ({s.risk_score:.1f})",
            f"Nodes             {s.node_count}",
            f"IOCs              {s.ioc_count}",
            f"Detections        {s.detection_count}",
            f"Relationships     {s.relationship_count}",
            f"Campaigns         {s.campaign_count}",
        ]
    )


def decode_tree(report: TitanReport, *, filter_text: str = "") -> str:
    """Depth-indented decode tree, optionally filtered."""

    needle = filter_text.lower().strip()
    lines = []
    for node in report.nodes():
        text = " ".join(
            str(node.get(key, ""))
            for key in (
                "method",
                "decoder_used",
                "content_type",
                "content_preview",
                "artifact_name",
            )
        )
        if needle and needle not in text.lower():
            continue
        depth = int(node.get("depth", 0) or 0)
        method = node.get("method") or node.get("decoder_used") or "input"
        node_id = node.get("id")
        if node_id is None:
            node_id = node.get("node_id", "?")
        content_type = node.get("content_type") or "unknown"
        lines.append(f"{'  ' * depth}• {method} [{content_type}] id={node_id}")
    return "\n".join(lines) or "No matching nodes."


def node_detail(report: TitanReport, node_id: Any) -> str:
    """Full detail for one node, with parent/children for navigation."""

    node = report.node_by_id(node_id)
    if node is None:
        return f"No node with id {node_id}."
    children = report.children_of(node.get("id"))
    preview = str(node.get("content_preview") or "").replace("\n", " ")
    if len(preview) > 200:
        preview = preview[:199] + "…"
    lines = [
        f"Node              {node.get('id')}",
        f"Parent            {node.get('parent') if node.get('parent') is not None else '(root)'}",
        f"Children          {', '.join(str(c.get('id')) for c in children) or 'none'}",
        f"Method            {node.get('method') or 'input'}",
        f"Decoder           {node.get('decoder_used') or '-'}",
        f"Content type      {node.get('content_type') or 'unknown'}",
        f"Depth             {node.get('depth', 0)}",
        f"Sizes             {node.get('source_length', '?')} → {node.get('decoded_length', '?')} bytes",
        f"SHA-256           {node.get('sha256') or '-'}",
        f"Entropy           {node.get('entropy', '-')}",
        f"Decode score      {node.get('decode_score', '-')}",
        f"Preview           {preview or '-'}",
    ]
    return "\n".join(lines)


def indicator_view(report: TitanReport, *, filter_text: str = "") -> str:
    needle = filter_text.lower().strip()
    lines = []
    for kind, value in report.indicators():
        if needle and needle not in f"{kind} {value}".lower():
            continue
        lines.append(f"{kind:<18} {value}")
    return "\n".join(lines) or "No matching indicators."


def detection_view(report: TitanReport, *, filter_text: str = "") -> str:
    needle = filter_text.lower().strip()
    lines = []
    for item in report.detections():
        if needle and needle not in str(item).lower():
            continue
        rule_id = item.get("rule_id") or item.get("id") or "?"
        severity = item.get("severity") or "unknown"
        name = item.get("name") or item.get("description") or ""
        attacks = ",".join(item.get("attack_ids") or [])
        suffix = f"  [{attacks}]" if attacks else ""
        lines.append(f"{severity:<9} {rule_id:<18} {name}{suffix}")
    return "\n".join(lines) or "No matching detections."


def timeline_view(report: TitanReport, *, filter_text: str = "") -> str:
    needle = filter_text.lower().strip()
    events = []
    for item in report.timeline():
        timestamp = str(item.get("timestamp") or item.get("time") or "")
        kind = str(
            item.get("kind") or item.get("event_type") or item.get("type") or "event"
        )
        summary = str(
            item.get("summary") or item.get("message") or item.get("description") or ""
        )
        if needle and needle not in f"{timestamp} {kind} {summary}".lower():
            continue
        events.append((timestamp, kind, summary))
    events.sort()
    return (
        "\n".join(f"{ts:<26} {kind:<16} {summary}" for ts, kind, summary in events)
        or "No matching timeline events."
    )


def evidence_view(report: TitanReport, *, filter_text: str = "") -> str:
    """DFIR evidence browser: indicators, top pivots, and top links."""

    evidence = report.evidence()
    if not evidence:
        return "No evidence attached to this report."
    needle = filter_text.lower().strip()

    lines = [
        f"Events            {len(evidence.get('events') or [])}",
        f"Indicators        {len(evidence.get('indicators') or [])}",
        "",
    ]
    shown = 0
    for item in evidence.get("indicators") or []:
        if not isinstance(item, dict):
            continue
        kind = str(item.get("indicator_type") or item.get("type") or "?")
        value = str(item.get("value") or "")
        if needle and needle not in f"{kind} {value}".lower():
            continue
        lines.append(f"{kind:<18} {value}")
        shown += 1
        if shown >= 100:
            lines.append("… (more indicators; refine the filter)")
            break
    if not shown:
        lines.append("No matching evidence indicators.")

    pivots = evidence.get("top_pivots") or []
    if pivots:
        lines += ["", "Top pivots:"]
        lines += [f"  {p}" for p in pivots[:10]]
    links = evidence.get("top_links") or []
    if links:
        lines += ["", "Top links:"]
        lines += [f"  {link}" for link in links[:10]]
    return "\n".join(lines)


def correlation_view(report: TitanReport) -> str:
    lines = []
    correlation = report.data.get("correlation") or {}
    for item in correlation.get("relationships") or []:
        lines.append(
            f"{item.get('left_analysis_id')} ↔ {item.get('right_analysis_id')} "
            f"score={float(item.get('score', 0)):.3f} confidence={item.get('confidence', '')}"
        )
    for item in (report.data.get("attribution_hints") or {}).get("hints") or []:
        lines.append(
            f"hint {item.get('left_analysis_id')} ↔ {item.get('right_analysis_id')} "
            f"{item.get('confidence')} score={float(item.get('score', 0)):.3f}"
        )
    campaigns = (report.data.get("campaigns") or {}).get("campaigns") or []
    for item in campaigns:
        members = ", ".join(item.get("member_analysis_ids") or [])
        lines.append(f"campaign [{item.get('confidence')}] members: {members}")
    return "\n".join(lines) or "No cross-case correlation data."
