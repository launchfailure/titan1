from __future__ import annotations

from html import escape
from typing import Any

from .models import AnalysisSnapshot


def short(value: Any, limit: int = 70) -> str:
    text = str(value).replace("\n", " ")
    return text if len(text) <= limit else text[: limit - 1] + "…"


def summary_text(snapshot: AnalysisSnapshot) -> str:
    if snapshot.decoder_label is not None:
        status = "Successful" if snapshot.decoder_success else "Failed"
        output_size = len(snapshot.decoded_output or b"")
        return (
            f"[b]Decoder[/b]      {snapshot.decoder_label}\n"
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
            lines.append(f"[b]{kind}[/b]  {len(values)}")
    if snapshot.detections:
        lines.append(f"[b]Detections[/b]  {len(snapshot.detections)}")
    if snapshot.relationships:
        lines.append(f"[b]Relationships[/b]  {len(snapshot.relationships)}")
    return "\n".join(lines) if lines else "No findings loaded."


def decode_tree_text(snapshot: AnalysisSnapshot) -> str:
    if not snapshot.nodes:
        return "No decode tree available."
    lines = []
    for node in snapshot.nodes[:300]:
        depth = int(node.get("depth", 0) or 0)
        method = node.get("method") or node.get("decoder_used") or "input"
        ctype = node.get("content_type") or "unknown"
        lines.append(f"{'  ' * depth}• {method} [{ctype}]")
    return "\n".join(lines)


def detections_text(snapshot: AnalysisSnapshot) -> str:
    if not snapshot.detections:
        return "No detections."
    lines = []
    for item in snapshot.detections[:250]:
        name = item.get("name") or item.get("rule_id") or item.get("id") or "detection"
        severity = item.get("severity") or item.get("risk") or "unknown"
        lines.append(f"• {name} — {severity}")
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
        lines.append(f"[b]{kind}[/b]")
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
        ascii_part = "".join(chr(value) if 32 <= value <= 126 else "." for value in chunk)
        rows.append(f"{offset:08x}  {hex_part:<47}  {ascii_part}")
    if len(data) > limit:
        rows.append(f"… {len(data) - limit} more bytes")
    return "\n".join(rows)


def decoded_text(snapshot: AnalysisSnapshot) -> str:
    data = snapshot.decoded_output
    if data is None:
        return "Run a decoder to inspect output."
    try:
        return escape(data.decode("utf-8", errors="replace")[:12000])
    except Exception:
        return hex_preview(data)


def timeline_text(snapshot: AnalysisSnapshot) -> str:
    events = []
    for item in snapshot.timeline:
        timestamp = str(item.get("timestamp") or item.get("time") or "")
        kind = str(item.get("kind") or item.get("event_type") or item.get("type") or "event")
        summary = str(item.get("summary") or item.get("message") or item.get("description") or "")
        events.append((timestamp, kind, summary))
    events.sort()
    if not events:
        return "No timeline events recorded in the active report."
    return "\n".join(f"{ts:<26} {kind:<18} {short(summary, 100)}" for ts, kind, summary in events[:500])


def correlation_text(snapshot: AnalysisSnapshot) -> str:
    lines = []
    for item in snapshot.relationships:
        lines.append(
            f"• {item.get('left_analysis_id', '?')} ↔ {item.get('right_analysis_id', '?')} "
            f"score={float(item.get('score', 0) or 0):.3f} confidence={item.get('confidence', '')}"
        )
    for item in (snapshot.report.get("attribution_hints") or {}).get("hints") or []:
        if isinstance(item, dict):
            lines.append(
                f"• attribution hint {item.get('left_analysis_id', '?')} ↔ "
                f"{item.get('right_analysis_id', '?')} confidence={item.get('confidence', '')}"
            )
    for item in (snapshot.report.get("campaigns") or {}).get("campaigns") or []:
        if isinstance(item, dict):
            members = ", ".join(map(str, item.get("member_analysis_ids") or []))
            lines.append(f"• campaign [{item.get('confidence', '')}] members: {members}")
    return "\n".join(lines) if lines else "No cross-case correlation data recorded in the active report."
