"""Case report generator for investigators / law enforcement.

Produces a structured dict and Markdown/HTML summaries combining:
- Intelligence assessment
- Indicators (IOCs)
- Forensic hints (VM/burner/mobile/timezone)
- Normalized evidence
- Recommendations
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Mapping, Sequence


def build_case_report(
    report: Dict[str, Any], forensics: Dict[str, Any] | None, iocs: Dict[str, Any]
) -> Dict[str, Any]:
    """Build the stable intermediate representation consumed by all renderers.

    The raw Intelligence Layer result is copied into the case object instead of
    being recomputed. This preserves deterministic scores, signal ordering, and
    artifact ranking across JSON, Markdown, and HTML outputs.
    """
    evidence = report.get("evidence") or {}
    assurance = _normalize_assurance(report.get("assurance"))
    intelligence = _normalize_intelligence(report.get("intelligence"))
    threat_intelligence = _normalize_threat_intelligence(
        report.get("threat_intelligence")
    )

    recommendations = _recommendations(forensics, iocs)
    analyst_recommendation = intelligence.get("recommendation")
    if analyst_recommendation and analyst_recommendation not in recommendations:
        recommendations.insert(0, analyst_recommendation)

    return {
        "meta": report.get("meta", {}),
        "node_count": report.get("node_count", 0),
        "assurance": assurance,
        "intelligence": intelligence,
        "threat_intelligence": threat_intelligence,
        "iocs": iocs,
        "forensics": forensics or {},
        "evidence": {
            "event_count": len(evidence.get("events") or []),
            "indicator_count": len(evidence.get("indicators") or []),
            "top_pivots": evidence.get("top_pivots") or [],
            "top_links": evidence.get("top_links") or [],
            "entity_hints": evidence.get("entity_hints") or {},
            "last_seen": evidence.get("last_seen") or {},
        }
        if evidence
        else {},
        "plugin_sections": list(report.get("plugin_report_sections") or []),
        "recommendations": recommendations,
    }


def to_markdown(case: Dict[str, Any]) -> str:
    lines: List[str] = []
    meta = case.get("meta", {})
    lines.append("# Titan Case Report")
    lines.append("")

    assurance = _normalize_assurance(case.get("assurance"))
    if assurance:
        lines.extend(_assurance_markdown(assurance))

    intelligence = _normalize_intelligence(case.get("intelligence"))
    if intelligence:
        lines.extend(_intelligence_markdown(intelligence))

    threat = _normalize_threat_intelligence(case.get("threat_intelligence"))
    if threat:
        lines.extend(_threat_markdown(threat))

    if meta:
        lines.append("## Meta")
        lines.append("")
        lines.append("```json")
        lines.append(json.dumps(meta, indent=2))
        lines.append("```")
        lines.append("")

    lines.append("## Indicators")
    lines.append("")
    iocs = case.get("iocs", {})
    if not iocs:
        lines.append("- None")
    else:
        for key, values in iocs.items():
            display = ", ".join(str(value) for value in values) if values else "None"
            lines.append(f"- **{key}:** {display}")
    lines.append("")

    ev = case.get("evidence") or {}
    if ev:
        lines.append("## Evidence (Normalized)")
        lines.append("")
        lines.append(f"- **Event count:** {ev.get('event_count', 0)}")
        lines.append(f"- **Indicator count:** {ev.get('indicator_count', 0)}")
        pivots = ev.get("top_pivots") or []
        if pivots:
            lines.append("")
            lines.append("### Top Pivots")
            lines.append("")
            for pivot in pivots[:10]:
                lines.append(
                    "- "
                    f"`{pivot.get('type')}={pivot.get('value')}` "
                    f"(sources={pivot.get('source_count')}, "
                    f"last_seen={pivot.get('last_seen')}, "
                    f"confidence={pivot.get('confidence')})"
                )

        entities = ev.get("entity_hints") or {}
        if entities:
            lines.append("")
            lines.append("### Entity Hints")
            lines.append("")
            lines.append("```json")
            lines.append(json.dumps(entities, indent=2))
            lines.append("```")

        links = ev.get("top_links") or []
        if links:
            lines.append("")
            lines.append("### Top Links")
            lines.append("")
            for link in links[:10]:
                src = link.get("src") or {}
                dst = link.get("dst") or {}
                lines.append(
                    "- "
                    f"`{src.get('type')}={src.get('value')}` → "
                    f"`{dst.get('type')}={dst.get('value')}` "
                    f"({link.get('reason_code')}, "
                    f"confidence={link.get('confidence')})"
                )
        lines.append("")

    lines.append("## Forensics")
    lines.append("")
    lines.append("```json")
    lines.append(json.dumps(case.get("forensics", {}) or {}, indent=2))
    lines.append("```")
    lines.append("")

    for section in case.get("plugin_sections") or []:
        if "markdown" not in (section.get("formats") or []):
            continue
        lines.append(f"## {_md_cell(section.get('title'))}")
        lines.append("")
        lines.append(f"_Contributed by plugin: {_md_cell(section.get('plugin'))}_")
        lines.append("")
        lines.append("```json")
        lines.append(json.dumps(section.get("content"), indent=2, sort_keys=True))
        lines.append("```")
        lines.append("")

    lines.append("## Recommendations")
    lines.append("")
    for recommendation in case.get("recommendations", []):
        lines.append(f"- {recommendation}")
    lines.append("")
    return "\n".join(lines)


def to_html(case: Dict[str, Any]) -> str:
    meta = case.get("meta", {})
    iocs = case.get("iocs", {})
    forensics = case.get("forensics", {}) or {}
    recs = case.get("recommendations", [])
    ev = case.get("evidence") or {}
    assurance = _normalize_assurance(case.get("assurance"))
    intelligence = _normalize_intelligence(case.get("intelligence"))
    threat = _normalize_threat_intelligence(case.get("threat_intelligence"))

    def esc(value: Any) -> str:
        return (
            str(value)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#39;")
        )

    ioc_rows = []
    for key, values in iocs.items():
        if not values:
            ioc_rows.append(f"<tr><td>{esc(key)}</td><td><em>None</em></td></tr>")
        else:
            joined = ", ".join(str(value) for value in values)
            ioc_rows.append(
                f"<tr><td>{esc(key)}</td><td><code>{esc(joined)}</code></td></tr>"
            )

    if not ioc_rows:
        ioc_rows.append("<tr><td colspan='2'><em>None</em></td></tr>")

    rec_items = "".join(f"<li>{esc(item)}</li>" for item in recs) or "<li>None</li>"

    pivots = ev.get("top_pivots") or []
    pivot_rows = []
    for pivot in pivots[:10]:
        pivot_rows.append(
            "<tr>"
            f"<td>{esc(pivot.get('type'))}</td>"
            f"<td><code>{esc(pivot.get('value'))}</code></td>"
            f"<td>{esc(pivot.get('confidence'))}</td>"
            f"<td>{esc(pivot.get('source_count'))}</td>"
            f"<td>{esc(pivot.get('last_seen'))}</td>"
            "</tr>"
        )

    assurance_html = _assurance_html(assurance, esc) if assurance else ""
    intelligence_html = _intelligence_html(intelligence, esc) if intelligence else ""
    threat_html = _threat_html(threat, esc) if threat else ""

    evidence_html = "<p><em>No evidence ingested.</em></p>"
    if ev:
        if pivot_rows:
            evidence_html = (
                "<table>"
                "<thead><tr><th>Type</th><th>Value</th><th>Confidence</th>"
                "<th>Sources</th><th>Last Seen</th></tr></thead>"
                f"<tbody>{''.join(pivot_rows)}</tbody>"
                "</table>"
            )
        else:
            evidence_html = f"<pre>{esc(json.dumps(ev, indent=2))}</pre>"

    return "\n".join(
        [
            "<!doctype html>",
            "<html lang='en'>",
            "<head>",
            "  <meta charset='utf-8'>",
            "  <meta name='viewport' content='width=device-width, initial-scale=1'>",
            "  <title>Titan Case Report</title>",
            "  <style>",
            "    body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 2rem; line-height: 1.45; }",
            "    code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }",
            "    pre { background: #f6f8fa; padding: 1rem; overflow-x: auto; }",
            "    table { border-collapse: collapse; width: 100%; margin-bottom: 1.5rem; }",
            "    th, td { border: 1px solid #ddd; padding: 0.5rem; vertical-align: top; }",
            "    th { background: #f2f2f2; text-align: left; }",
            "    .intelligence-summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(10rem, 1fr)); gap: 0.75rem; margin-bottom: 1rem; }",
            "    .metric { border: 1px solid #ddd; border-radius: 0.4rem; padding: 0.75rem; }",
            "    .metric-label { color: #555; display: block; font-size: 0.85rem; }",
            "    .metric-value { display: block; font-size: 1.2rem; font-weight: 700; }",
            "  </style>",
            "</head>",
            "<body>",
            "  <h1>Titan Case Report</h1>",
            assurance_html,
            intelligence_html,
            threat_html,
            "  <h2>Meta</h2>",
            f"  <pre>{esc(json.dumps(meta, indent=2))}</pre>",
            "  <h2>Indicators</h2>",
            "  <table>",
            "    <thead><tr><th>Type</th><th>Values</th></tr></thead>",
            "    <tbody>",
            *["    " + row for row in ioc_rows],
            "    </tbody>",
            "  </table>",
            "  <h2>Forensics</h2>",
            f"  <pre>{esc(json.dumps(forensics, indent=2))}</pre>",
            "  <h2>Evidence (Normalized)</h2>",
            f"  {evidence_html}",
            _plugin_sections_html(case, esc),
            "  <h2>Recommendations</h2>",
            f"  <ul>{rec_items}</ul>",
            "</body>",
            "</html>",
        ]
    )


def _normalize_assurance(value: Any) -> Dict[str, Any]:
    """Return a renderer-safe copy of an Assurance v1-compatible object."""
    if not isinstance(value, Mapping) or not value:
        return {}
    controls = value.get("controls")
    blockers = value.get("blockers")
    return {
        "version": value.get("version"),
        "verdict": value.get("verdict"),
        "confidence": value.get("confidence"),
        "summary": value.get("summary"),
        "controls_satisfied": value.get("controls_satisfied"),
        "controls_total": value.get("controls_total"),
        "controls": list(controls)
        if isinstance(controls, Sequence) and not isinstance(controls, (str, bytes))
        else [],
        "blockers": list(blockers)
        if isinstance(blockers, Sequence) and not isinstance(blockers, (str, bytes))
        else [],
        "safety_claim": value.get("safety_claim"),
    }


def _assurance_markdown(assurance: Dict[str, Any]) -> List[str]:
    lines = [
        "## Assurance Verdict",
        "",
        f"- **Verdict:** {assurance.get('verdict') or 'NOT ASSESSED'}",
        f"- **Confidence:** {_format_confidence(assurance.get('confidence'))}",
        "- **Controls satisfied:** "
        f"{assurance.get('controls_satisfied', 0)}/{assurance.get('controls_total', 6)}",
        f"- **Summary:** {assurance.get('summary') or 'No summary available.'}",
        f"- **Safety claim:** {assurance.get('safety_claim') or 'None'}",
        "",
        "### Assurance Controls",
        "",
        "| Control | State | Summary |",
        "|---|---|---|",
    ]
    for control in assurance.get("controls") or []:
        if not isinstance(control, Mapping):
            continue
        lines.append(
            f"| {_md_cell(control.get('label') or control.get('id'))} | "
            f"{_md_cell(control.get('state'))} | "
            f"{_md_cell(control.get('summary'))} |"
        )
    lines.append("")
    return lines


def _assurance_html(assurance: Dict[str, Any], esc) -> str:
    rows = []
    for control in assurance.get("controls") or []:
        if not isinstance(control, Mapping):
            continue
        rows.append(
            "<tr>"
            f"<td>{esc(control.get('label') or control.get('id'))}</td>"
            f"<td>{esc(control.get('state'))}</td>"
            f"<td>{esc(control.get('summary'))}</td>"
            "</tr>"
        )
    return "\n".join(
        [
            "  <section id='assurance'>",
            "    <h2>Assurance Verdict</h2>",
            "    <div class='intelligence-summary'>",
            "      <div class='metric'><span class='metric-label'>Verdict</span>"
            f"<span class='metric-value'>{esc(assurance.get('verdict') or 'NOT ASSESSED')}</span></div>",
            "      <div class='metric'><span class='metric-label'>Controls</span>"
            f"<span class='metric-value'>{esc(assurance.get('controls_satisfied', 0))}/{esc(assurance.get('controls_total', 6))}</span></div>",
            "    </div>",
            f"    <p>{esc(assurance.get('summary') or '')}</p>",
            f"    <p><strong>Safety claim:</strong> {esc(assurance.get('safety_claim') or 'None')}</p>",
            "    <table>",
            "      <thead><tr><th>Control</th><th>State</th><th>Summary</th></tr></thead>",
            f"      <tbody>{''.join(rows)}</tbody>",
            "    </table>",
            "  </section>",
        ]
    )


def _plugin_sections_html(case: Dict[str, Any], esc) -> str:
    """Render plugin-contributed sections (html format) as HTML blocks."""
    blocks: List[str] = []
    for section in case.get("plugin_sections") or []:
        if "html" not in (section.get("formats") or []):
            continue
        blocks.append(f"  <h2>{esc(section.get('title'))}</h2>")
        blocks.append(
            f"  <p><em>Contributed by plugin: {esc(section.get('plugin'))}</em></p>"
        )
        content = json.dumps(section.get("content"), indent=2, sort_keys=True)
        blocks.append(f"  <pre>{esc(content)}</pre>")
    return "\n".join(blocks)


def _normalize_intelligence(value: Any) -> Dict[str, Any]:
    """Return a renderer-safe copy of an Intelligence v1-compatible object."""
    if not isinstance(value, Mapping) or not value:
        return {}

    signals = value.get("signals")
    artifacts = value.get("top_artifacts")
    return {
        "version": value.get("version"),
        "intelligence_score": value.get("intelligence_score"),
        "classification": value.get("classification"),
        "confidence": value.get("confidence"),
        "signals": list(signals)
        if isinstance(signals, Sequence) and not isinstance(signals, (str, bytes))
        else [],
        "top_artifacts": list(artifacts)
        if isinstance(artifacts, Sequence) and not isinstance(artifacts, (str, bytes))
        else [],
        "recommendation": value.get("recommendation"),
    }


def _intelligence_markdown(intelligence: Dict[str, Any]) -> List[str]:
    lines = [
        "## Intelligence Assessment",
        "",
        f"- **Classification:** {intelligence.get('classification') or 'UNKNOWN'}",
        f"- **Score:** {intelligence.get('intelligence_score', 0)}/100",
        f"- **Confidence:** {_format_confidence(intelligence.get('confidence'))}",
        f"- **Contract version:** {intelligence.get('version') or 'Unknown'}",
    ]

    recommendation = intelligence.get("recommendation")
    if recommendation:
        lines.append(f"- **Analyst recommendation:** {recommendation}")

    signals = intelligence.get("signals") or []
    lines.extend(["", "### Top Signals", ""])
    if not signals:
        lines.append("- None")
    else:
        for signal in signals[:10]:
            if not isinstance(signal, Mapping):
                continue
            lines.append(
                f"- **{signal.get('code', 'unknown')}** "
                f"(+{signal.get('points', 0)}): {signal.get('summary', '')}"
            )
            evidence = signal.get("evidence")
            if evidence not in (None, "", [], {}):
                lines.append(f"  - Evidence: `{_compact_json(evidence)}`")

    artifacts = intelligence.get("top_artifacts") or []
    lines.extend(["", "### Highest-Priority Artifacts", ""])
    if not artifacts:
        lines.append("- None")
    else:
        lines.append("| Rank | Node | Artifact | Method | Score | Reasons |")
        lines.append("|---:|---:|---|---|---:|---|")
        for rank, artifact in enumerate(artifacts[:5], start=1):
            if not isinstance(artifact, Mapping):
                continue
            reasons = ", ".join(str(reason) for reason in artifact.get("reasons") or [])
            lines.append(
                f"| {rank} | {_md_cell(artifact.get('node_id'))} | "
                f"{_md_cell(artifact.get('artifact_name') or '—')} | "
                f"{_md_cell(artifact.get('method') or '—')} | "
                f"{_md_cell(artifact.get('score', 0))} | {_md_cell(reasons or '—')} |"
            )
    lines.append("")
    return lines


def _intelligence_html(intelligence: Dict[str, Any], esc) -> str:
    signals = intelligence.get("signals") or []
    artifacts = intelligence.get("top_artifacts") or []

    signal_items = []
    for signal in signals[:10]:
        if not isinstance(signal, Mapping):
            continue
        evidence = signal.get("evidence")
        evidence_html = ""
        if evidence not in (None, "", [], {}):
            evidence_html = (
                f" <small>Evidence: <code>{esc(_compact_json(evidence))}</code></small>"
            )
        signal_items.append(
            "<li>"
            f"<strong>{esc(signal.get('code', 'unknown'))}</strong> "
            f"(+{esc(signal.get('points', 0))}): "
            f"{esc(signal.get('summary', ''))}"
            f"{evidence_html}"
            "</li>"
        )
    if not signal_items:
        signal_items.append("<li>None</li>")

    artifact_rows = []
    for rank, artifact in enumerate(artifacts[:5], start=1):
        if not isinstance(artifact, Mapping):
            continue
        reasons = ", ".join(str(reason) for reason in artifact.get("reasons") or [])
        artifact_rows.append(
            "<tr>"
            f"<td>{rank}</td>"
            f"<td>{esc(artifact.get('node_id'))}</td>"
            f"<td>{esc(artifact.get('artifact_name') or '—')}</td>"
            f"<td>{esc(artifact.get('method') or '—')}</td>"
            f"<td>{esc(artifact.get('score', 0))}</td>"
            f"<td>{esc(reasons or '—')}</td>"
            "</tr>"
        )
    if not artifact_rows:
        artifact_rows.append("<tr><td colspan='6'><em>None</em></td></tr>")

    recommendation = intelligence.get("recommendation")
    recommendation_html = (
        f"<p><strong>Analyst recommendation:</strong> {esc(recommendation)}</p>"
        if recommendation
        else ""
    )

    return "\n".join(
        [
            "  <section id='intelligence'>",
            "    <h2>Intelligence Assessment</h2>",
            "    <div class='intelligence-summary'>",
            "      <div class='metric'><span class='metric-label'>Classification</span>"
            f"<span class='metric-value'>{esc(intelligence.get('classification') or 'UNKNOWN')}</span></div>",
            "      <div class='metric'><span class='metric-label'>Score</span>"
            f"<span class='metric-value'>{esc(intelligence.get('intelligence_score', 0))}/100</span></div>",
            "      <div class='metric'><span class='metric-label'>Confidence</span>"
            f"<span class='metric-value'>{esc(_format_confidence(intelligence.get('confidence')))}</span></div>",
            "      <div class='metric'><span class='metric-label'>Contract version</span>"
            f"<span class='metric-value'>{esc(intelligence.get('version') or 'Unknown')}</span></div>",
            "    </div>",
            f"    {recommendation_html}",
            "    <h3>Top Signals</h3>",
            f"    <ul>{''.join(signal_items)}</ul>",
            "    <h3>Highest-Priority Artifacts</h3>",
            "    <table>",
            "      <thead><tr><th>Rank</th><th>Node</th><th>Artifact</th><th>Method</th><th>Score</th><th>Reasons</th></tr></thead>",
            f"      <tbody>{''.join(artifact_rows)}</tbody>",
            "    </table>",
            "  </section>",
        ]
    )


def _normalize_threat_intelligence(value: Any) -> Dict[str, Any]:
    if not isinstance(value, Mapping) or not value:
        return {}
    return {
        "version": value.get("version"),
        "catalog_version": value.get("catalog_version"),
        "techniques": list(value.get("techniques") or []),
        "tactics": list(value.get("tactics") or []),
        "lolbins": list(value.get("lolbins") or []),
        "malware_tags": list(value.get("malware_tags") or []),
        "confidence": value.get("confidence"),
        "summary": value.get("summary"),
    }


def _threat_markdown(threat: Dict[str, Any]) -> List[str]:
    lines = [
        "## Threat Intelligence",
        "",
        f"- **Confidence:** {_format_confidence(threat.get('confidence'))}",
        f"- **Catalog:** {threat.get('catalog_version') or 'Unknown'}",
        f"- **Summary:** {threat.get('summary') or 'None'}",
        "",
        "### MITRE ATT&CK",
        "",
    ]
    techniques = threat.get("techniques") or []
    if not techniques:
        lines.append("- None")
    else:
        lines.append("| Technique | Name | Tactics | Confidence |")
        lines.append("|---|---|---|---:|")
        for item in techniques:
            lines.append(
                f"| {_md_cell(item.get('technique_id'))} | "
                f"{_md_cell(item.get('name'))} | "
                f"{_md_cell(', '.join(item.get('tactics') or []))} | "
                f"{_format_confidence(item.get('confidence'))} |"
            )
    lines.extend(["", "### LOLBins", ""])
    lolbins = threat.get("lolbins") or []
    if not lolbins:
        lines.append("- None")
    else:
        for item in lolbins:
            lines.append(
                f"- **{item.get('executable')}** — "
                f"{', '.join(item.get('technique_ids') or [])} "
                f"({_format_confidence(item.get('confidence'))})"
            )
    lines.extend(["", "### Behavioral Malware Tags", ""])
    tags = threat.get("malware_tags") or []
    if not tags:
        lines.append("- None")
    else:
        for item in tags:
            lines.append(
                f"- **{item.get('tag')}** ({item.get('category')}, "
                f"{_format_confidence(item.get('confidence'))}): "
                f"{'; '.join(item.get('reasons') or [])}"
            )
    lines.append("")
    return lines


def _threat_html(threat: Dict[str, Any], esc) -> str:
    rows = []
    for item in threat.get("techniques") or []:
        rows.append(
            "<tr>"
            f"<td><code>{esc(item.get('technique_id'))}</code></td>"
            f"<td>{esc(item.get('name'))}</td>"
            f"<td>{esc(', '.join(item.get('tactics') or []))}</td>"
            f"<td>{esc(_format_confidence(item.get('confidence')))}</td>"
            "</tr>"
        )
    if not rows:
        rows.append("<tr><td colspan='4'><em>None</em></td></tr>")
    lolbins = (
        "".join(
            f"<li><strong>{esc(item.get('executable'))}</strong> — "
            f"{esc(', '.join(item.get('technique_ids') or []))}</li>"
            for item in threat.get("lolbins") or []
        )
        or "<li>None</li>"
    )
    tags = (
        "".join(
            f"<li><strong>{esc(item.get('tag'))}</strong> "
            f"({esc(item.get('category'))})</li>"
            for item in threat.get("malware_tags") or []
        )
        or "<li>None</li>"
    )
    return "\n".join(
        [
            "  <section id='threat-intelligence'>",
            "    <h2>Threat Intelligence</h2>",
            f"    <p><strong>Confidence:</strong> {esc(_format_confidence(threat.get('confidence')))}</p>",
            f"    <p>{esc(threat.get('summary') or '')}</p>",
            "    <h3>MITRE ATT&CK</h3>",
            "    <table><thead><tr><th>Technique</th><th>Name</th><th>Tactics</th><th>Confidence</th></tr></thead>",
            f"    <tbody>{''.join(rows)}</tbody></table>",
            "    <h3>LOLBins</h3>",
            f"    <ul>{lolbins}</ul>",
            "    <h3>Behavioral Malware Tags</h3>",
            f"    <ul>{tags}</ul>",
            "  </section>",
        ]
    )


def _format_confidence(value: Any) -> str:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return "Unknown"
    return f"{number:.0%}"


def _compact_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _md_cell(value: Any) -> str:
    return str(value).replace("|", r"\|").replace("\n", " ")


def _recommendations(
    forensics: Dict[str, Any] | None, iocs: Dict[str, Any]
) -> List[str]:
    recs: List[str] = []
    if not forensics:
        recs.append("Review IOCs; consider correlation with prior incidents.")
        return recs

    vm = (forensics or {}).get("vm", {})
    if vm.get("detected"):
        recs.append(
            "VM artifacts present—consider staging/test environment attribution."
        )

    burner = (forensics or {}).get("burner", {})
    if burner.get("score", 0) >= 0.5:
        recs.append(
            "Burner indicators present—correlate across incidents for reuse patterns."
        )

    mobile = (forensics or {}).get("mobile_ids", {})
    if any(mobile.values()):
        recs.append("Mobile IDs found—law enforcement can subpoena carrier/retailer.")

    tz = (forensics or {}).get("timezone_hints", [])
    if tz:
        recs.append(f"Timezone hints found: {', '.join(tz)}")

    if not recs:
        recs.append(
            "No strong forensic indicators—focus on infrastructure and IOC correlation."
        )
    return recs
