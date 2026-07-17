from __future__ import annotations

import math
import re
from typing import Any

from .models import AnalysisSnapshot


_RICH_MARKUP = re.compile(r"(\\*)(\[[a-z#/@][^[]*?)", re.IGNORECASE)


def markup_escape(value: Any) -> str:
    """Escape untrusted text while keeping the lightweight package dependency-free."""
    markup = str(value)

    def escape_match(match: re.Match[str]) -> str:
        backslashes, tag = match.groups()
        return f"{backslashes}{backslashes}\\{tag}"

    escaped = _RICH_MARKUP.sub(escape_match, markup)
    if escaped.endswith("\\") and not escaped.endswith("\\\\"):
        escaped += "\\"
    return escaped


def short(value: Any, limit: int = 70) -> str:
    text = str(value).replace("\n", " ")
    shortened = text if len(text) <= limit else text[: limit - 1] + "…"
    return markup_escape(shortened)


def summary_text(snapshot: AnalysisSnapshot) -> str:
    if snapshot.decoder_label is not None:
        status = "Successful" if snapshot.decoder_success else "Failed"
        output_size = len(snapshot.decoded_output or b"")
        return (
            f"[b]Decoder[/b]      {markup_escape(snapshot.decoder_label)}\n"
            f"[b]Status[/b]       {status}\n"
            f"[b]Input bytes[/b]  {snapshot.source_size}\n"
            f"[b]Output bytes[/b] {output_size}\n"
            f"[b]Duration[/b]     {snapshot.duration_seconds:.2f}s"
        )

    nodes = snapshot.nodes
    return (
        f"[b]Status[/b]          Completed\n"
        f"[b]Profile[/b]         Titan engine\n"
        f"[b]Duration[/b]        {snapshot.duration_seconds:.2f}s\n"
        f"[b]Decode nodes[/b]    {len(nodes)}\n"
        f"[b]Artifacts found[/b] {max(len(nodes) - 1, 0)}\n"
        f"[b]IOCs extracted[/b]  {snapshot.ioc_count}"
    )


def findings_text(snapshot: AnalysisSnapshot) -> str:
    lines: list[str] = []
    for kind, values in sorted(snapshot.iocs.items()):
        if values:
            lines.append(f"[b]{markup_escape(kind)}[/b]  {len(values)}")
    if snapshot.detections:
        lines.append(f"[b]Detections[/b]  {len(snapshot.detections)}")
    if snapshot.relationships:
        lines.append(f"[b]Relationships[/b]  {len(snapshot.relationships)}")
    if lines:
        return "\n".join(lines)
    if snapshot.report:
        # An analysis ran but surfaced no indicators; without this hint the
        # empty card reads as if decoding itself failed.
        return (
            "No indicators or detections extracted.\n"
            "Decoded content is in the DECODE TREE and HEX VIEW tabs."
        )
    return "No findings loaded."


def decode_tree_text(snapshot: AnalysisSnapshot) -> str:
    if not snapshot.nodes:
        return "No decode tree available."
    lines = []
    for node in snapshot.nodes[:300]:
        try:
            depth = int(node.get("depth", 0) or 0)
        except (TypeError, ValueError):
            depth = 0
        depth = min(max(depth, 0), 50)
        method = node.get("method") or node.get("decoder_used") or "input"
        ctype = node.get("content_type") or "unknown"
        lines.append(
            f"{'  ' * depth}• {markup_escape(method)} [{markup_escape(ctype)}]"
        )
    return "\n".join(lines)


def detections_text(snapshot: AnalysisSnapshot) -> str:
    if not snapshot.detections:
        return "No detections."
    lines = []
    for item in snapshot.detections[:250]:
        name = item.get("name") or item.get("rule_id") or item.get("id") or "detection"
        severity = item.get("severity") or item.get("risk") or "unknown"
        lines.append(f"• {markup_escape(name)} — {markup_escape(severity)}")
    return "\n".join(lines)


def strings_text(snapshot: AnalysisSnapshot) -> str:
    if not snapshot.strings:
        return "No interesting strings."
    return "\n".join(f"• {short(value, 120)}" for value in snapshot.strings[:500])


def iocs_text(snapshot: AnalysisSnapshot) -> str:
    if not snapshot.iocs:
        return "No IOCs."
    lines = []
    for kind, values in sorted(snapshot.iocs.items()):
        lines.append(f"[b]{markup_escape(kind)}[/b]")
        lines.extend(f"  • {short(value, 120)}" for value in values[:100])
    return "\n".join(lines)


def hex_preview(data: bytes | None, limit: int = 1024) -> str:
    if not data:
        return "No binary output."
    rows = []
    view = data[:limit]
    for offset in range(0, len(view), 16):
        chunk = view[offset : offset + 16]
        hex_part = " ".join(f"{value:02x}" for value in chunk)
        ascii_part = "".join(
            chr(value) if 32 <= value <= 126 else "." for value in chunk
        )
        rows.append(f"{offset:08x}  {hex_part:<47}  {ascii_part}")
    if len(data) > limit:
        rows.append(f"… {len(data) - limit} more bytes")
    return "\n".join(rows)


def decoded_text(snapshot: AnalysisSnapshot) -> str:
    data = snapshot.decoded_output
    if data is None:
        return "Run a decoder to inspect output."
    try:
        return markup_escape(data.decode("utf-8", errors="replace")[:12000])
    except Exception:
        return hex_preview(data)


def timeline_text(snapshot: AnalysisSnapshot) -> str:
    events = []
    for item in snapshot.timeline:
        timestamp = str(item.get("timestamp") or item.get("time") or "")
        kind = str(
            item.get("kind") or item.get("event_type") or item.get("type") or "event"
        )
        summary = str(
            item.get("summary") or item.get("message") or item.get("description") or ""
        )
        events.append((timestamp, kind, summary))
    events.sort()
    if not events:
        return "No timeline events recorded in the active report."
    return "\n".join(
        f"{markup_escape(ts):<26} {markup_escape(kind):<18} {short(summary, 100)}"
        for ts, kind, summary in events[:500]
    )


def correlation_text(snapshot: AnalysisSnapshot) -> str:
    lines = []
    for item in snapshot.relationships:
        try:
            score = float(item.get("score", 0) or 0)
        except (TypeError, ValueError):
            score = 0.0
        if not math.isfinite(score):
            score = 0.0
        lines.append(
            f"• {markup_escape(item.get('left_analysis_id', '?'))} ↔ "
            f"{markup_escape(item.get('right_analysis_id', '?'))} "
            f"score={score:.3f} "
            f"confidence={markup_escape(item.get('confidence', ''))}"
        )
    attribution = snapshot.report.get("attribution_hints")
    hints = attribution.get("hints") if isinstance(attribution, dict) else []
    for item in hints if isinstance(hints, list) else []:
        if isinstance(item, dict):
            lines.append(
                f"• attribution hint {markup_escape(item.get('left_analysis_id', '?'))} ↔ "
                f"{markup_escape(item.get('right_analysis_id', '?'))} "
                f"confidence={markup_escape(item.get('confidence', ''))}"
            )
    campaigns_group = snapshot.report.get("campaigns")
    campaigns = (
        campaigns_group.get("campaigns") if isinstance(campaigns_group, dict) else []
    )
    for item in campaigns if isinstance(campaigns, list) else []:
        if isinstance(item, dict):
            raw_members = item.get("member_analysis_ids")
            if not isinstance(raw_members, list):
                raw_members = []
            members = ", ".join(markup_escape(member) for member in raw_members)
            confidence = markup_escape(item.get("confidence", ""))
            lines.append(f"• campaign [{confidence}] members: {members}")
    return (
        "\n".join(lines)
        if lines
        else "No cross-case correlation data recorded in the active report."
    )
