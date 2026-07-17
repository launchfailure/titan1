"""Adapters that build correlation inputs from Titan analysis reports.

The correlation layer works with normalized :class:`AnalysisRecord` and
:class:`TimelineEvent` values. These adapters translate the engine's report
dictionary (``meta``, ``nodes``, ``iocs``, ``detections``,
``threat_intelligence``, ``evidence``) into those records so the rest of
Phase 5 never touches raw report shapes.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

from .models import AnalysisRecord, EvidenceReference, IndicatorRecord
from .timeline import TimelineEvent

# Evidence-event fields that identify what an event touched. Only these are
# carried into TimelineEvent.metadata so cross-case matching compares real
# observables instead of bookkeeping fields (event_id, extracted_by, raw).
_EVENT_OBSERVABLE_FIELDS = (
    "host",
    "user",
    "src_ip",
    "dst_ip",
    "domain",
    "url",
    "process",
    "file_path",
    "sha256",
)


def _string_values(value: Any) -> tuple[str, ...]:
    """Coerce a report field into a sorted tuple of non-empty strings."""

    if value is None:
        return ()
    if isinstance(value, str):
        return (value,) if value else ()
    if isinstance(value, Mapping):
        value = value.keys()
    if not isinstance(value, Iterable):
        return (str(value),)
    return tuple(sorted({str(item) for item in value if str(item)}))


def _analysis_id(report: Mapping[str, Any]) -> str:
    meta = report.get("meta") or {}
    return str(
        meta.get("analysis_id")
        or report.get("analysis_id")
        or report.get("root_hash")
        or ""
    )


def _root_hash(report: Mapping[str, Any]) -> str:
    """Return the root artifact hash for a report.

    Engine reports do not carry a top-level ``root_hash``; the canonical
    value is the sha256 of the root node (the node without a parent).
    """

    meta = report.get("meta") or {}
    explicit = report.get("root_hash") or meta.get("root_hash")
    if explicit:
        return str(explicit)
    for node in report.get("nodes") or ():
        if isinstance(node, Mapping) and node.get("parent") is None:
            sha256 = node.get("sha256")
            if sha256:
                return str(sha256)
    return ""


def _decode_chain(report: Mapping[str, Any]) -> tuple[str, ...]:
    chain: list[str] = []
    for node in report.get("nodes") or ():
        if not isinstance(node, Mapping):
            continue
        operation = node.get("decoder_used") or node.get("method")
        if operation:
            chain.append(str(operation))
    return tuple(chain)


def _indicators(
    report: Mapping[str, Any], analysis_id: str
) -> tuple[IndicatorRecord, ...]:
    indicators: list[IndicatorRecord] = []
    iocs = report.get("iocs") or {}
    if not isinstance(iocs, Mapping):
        return ()
    for kind in sorted(iocs):
        items = iocs[kind]
        if isinstance(items, (str, bytes, Mapping)):
            items = (items,)
        if not isinstance(items, Iterable):
            continue
        for item in items:
            if isinstance(item, Mapping):
                value = (
                    item.get("value")
                    or item.get("normalized_value")
                    or item.get("indicator")
                )
                node_id = item.get("node_id")
                evidence_id = item.get("evidence_id") or item.get("id")
            else:
                value, node_id, evidence_id = item, None, None
            if value is None or not str(value).strip():
                continue
            indicators.append(
                IndicatorRecord(
                    analysis_id=analysis_id,
                    indicator_type=str(kind),
                    value=str(value).strip(),
                    references=(
                        EvidenceReference(
                            analysis_id=analysis_id,
                            node_id=str(node_id) if node_id is not None else None,
                            evidence_id=str(evidence_id)
                            if evidence_id is not None
                            else None,
                            source="report.iocs",
                        ),
                    ),
                )
            )
    return tuple(indicators)


def _attack_ids_and_tags(
    report: Mapping[str, Any],
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    attacks: set[str] = set()
    tags: set[str] = set()

    for detection in report.get("detections") or ():
        if isinstance(detection, Mapping):
            attacks.update(_string_values(detection.get("attack_ids")))
            attacks.update(_string_values(detection.get("mitre_attack")))

    threat = report.get("threat_intelligence") or {}
    if isinstance(threat, Mapping):
        for technique in threat.get("techniques") or ():
            if isinstance(technique, Mapping) and technique.get("technique_id"):
                attacks.add(str(technique["technique_id"]))
        tags.update(_string_values(threat.get("malware_tags")))
        for lolbin in threat.get("lolbins") or ():
            if isinstance(lolbin, Mapping) and lolbin.get("name"):
                tags.add(f"lolbin:{lolbin['name']}")
            elif isinstance(lolbin, str) and lolbin:
                tags.add(f"lolbin:{lolbin}")

    return tuple(sorted(attacks)), tuple(sorted(tags))


def analysis_record_from_report(report: Mapping[str, Any]) -> AnalysisRecord:
    """Build the persistence-safe :class:`AnalysisRecord` for one report."""

    analysis_id = _analysis_id(report)
    if not analysis_id:
        raise ValueError("report has no analysis identifier")
    root_hash = _root_hash(report)
    if not root_hash:
        raise ValueError("report has no root hash (missing root node sha256)")

    meta = report.get("meta") or {}
    created_at = (
        meta.get("started_at") or meta.get("created_at") or report.get("created_at")
    )
    attack_ids, threat_tags = _attack_ids_and_tags(report)

    return AnalysisRecord(
        analysis_id=analysis_id,
        root_hash=root_hash,
        created_at=str(created_at) if created_at else None,
        indicators=_indicators(report, analysis_id),
        attack_ids=attack_ids,
        threat_tags=threat_tags,
        decode_chain=_decode_chain(report),
        metadata={"node_count": report.get("node_count")},
    )


def timeline_events_from_report(report: Mapping[str, Any]) -> tuple[TimelineEvent, ...]:
    """Extract timestamped, normalized events from one report.

    DFIR evidence events (``report["evidence"]["events"]``) are the primary
    source because they carry real wall-clock timestamps. Generic
    ``report["timeline"]`` / ``report["events"]`` entries are also accepted
    for callers that assemble reports by hand.
    """

    analysis_id = _analysis_id(report) or "analysis"
    events: list[TimelineEvent] = []

    evidence = report.get("evidence") or {}
    evidence_events = evidence.get("events") if isinstance(evidence, Mapping) else None
    sources: tuple[Any, ...] = (
        evidence_events,
        report.get("timeline"),
        report.get("events"),
    )
    for source in sources:
        if not isinstance(source, Iterable) or isinstance(
            source, (str, bytes, Mapping)
        ):
            continue
        for index, item in enumerate(source):
            if not isinstance(item, Mapping):
                continue
            timestamp = (
                item.get("timestamp") or item.get("time") or item.get("created_at")
            )
            if not timestamp:
                continue
            kind = str(
                item.get("event_type")
                or item.get("kind")
                or item.get("type")
                or "event"
            )
            summary = str(
                item.get("summary")
                or item.get("message")
                or item.get("description")
                or kind
            )
            # Keep only scalar observable values: comparing None or nested
            # structures across cases would manufacture false matches.
            metadata = {
                key: item[key]
                for key in _EVENT_OBSERVABLE_FIELDS
                if isinstance(item.get(key), (str, int, float)) and item.get(key) != ""
            }
            for key, value in item.items():
                if key in metadata or key in {
                    "timestamp",
                    "time",
                    "created_at",
                    "kind",
                    "event_type",
                    "type",
                    "summary",
                    "message",
                    "description",
                    "event_id",
                    "id",
                    "source",
                    "extracted_by",
                    "raw",
                    "tags",
                }:
                    continue
                if isinstance(value, (str, int, float)) and value != "":
                    metadata[key] = value
            try:
                events.append(
                    TimelineEvent(
                        analysis_id=analysis_id,
                        timestamp=str(timestamp),
                        kind=kind,
                        summary=summary,
                        source_id=str(
                            item.get("event_id")
                            or item.get("id")
                            or f"{analysis_id}:{index}"
                        ),
                        metadata=metadata,
                    )
                )
            except ValueError:
                # Unparseable timestamps are skipped rather than failing the
                # whole correlation run.
                continue
    return tuple(events)
