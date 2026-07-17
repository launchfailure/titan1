"""Canonical evidence models for Titan Decoder.

These models normalize heterogeneous DFIR inputs (files, logs, endpoint artifacts)
into a single schema that supports correlation, timelines, and defensible
provenance.

Design goals:
- Dependency-free and offline-friendly
- Best-effort parsing; never crash the run on a single bad record
- Preserve provenance (where a fact came from)
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# Monotonic counter for event IDs. Wall-clock-based IDs collided for events
# created in the same microsecond and made otherwise-identical runs produce
# different reports (event_id is also a sort tiebreaker downstream).
_EVENT_COUNTER = itertools.count(1)


def _next_event_id() -> str:
    return f"evt_{next(_EVENT_COUNTER):08d}"


def parse_timestamp(value: Any) -> Optional[str]:
    """Parse common timestamp formats into ISO-8601 UTC where possible.

    Returns ISO string (timezone-aware) or None.

    Supported inputs:
    - ISO 8601 strings
    - epoch seconds (int/float or numeric strings)
    - common log formats like "YYYY-mm-dd HH:MM:SS" (assumed UTC)
    """
    if value is None:
        return None

    def _from_epoch(num: float) -> Optional[str]:
        # Millisecond epochs (common in log exports) are ~1e12 for current
        # dates; second epochs stay below ~1e11 until the year 5138. Without
        # this, a 13-digit ms timestamp parsed as seconds lands in year ~56000.
        try:
            if abs(num) >= 1e11:
                num /= 1000.0
            return datetime.fromtimestamp(num, tz=timezone.utc).isoformat()
        except Exception:
            return None

    if isinstance(value, (int, float)):
        return _from_epoch(float(value))

    if isinstance(value, str):
        v = value.strip()
        if not v:
            return None

        # Numeric epoch string
        if v.isdigit():
            parsed = _from_epoch(float(v))
            if parsed is not None:
                return parsed

        # ISO 8601-ish
        try:
            # Handle trailing Z
            if v.endswith("Z") and "+" not in v:
                v = v[:-1] + "+00:00"
            dt = datetime.fromisoformat(v)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).isoformat()
        except Exception:
            pass

        # Common "YYYY-mm-dd HH:MM:SS" format (assume UTC)
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S"):
            try:
                dt = datetime.strptime(v, fmt).replace(tzinfo=timezone.utc)
                return dt.isoformat()
            except Exception:
                continue

    return None


def normalize_indicator_type(indicator_type: str) -> str:
    t = (indicator_type or "").strip().lower()
    mapping = {
        "ip": "ipv4",
        "ipv4": "ipv4",
        "ipv4_public": "ipv4_public",
        "domain": "domains",
        "domains": "domains",
        "url": "urls",
        "urls": "urls",
        "email": "emails",
        "emails": "emails",
        "sha256": "hashes",
        "hash": "hashes",
        "hashes": "hashes",
        "user": "users",
        "account": "users",
        "users": "users",
        "hostname": "hostnames",
        "host": "hostnames",
        "hostnames": "hostnames",
        "mac": "mac_addresses",
        "mac_address": "mac_addresses",
        "mac_addresses": "mac_addresses",
        "ua": "user_agents",
        "user_agent": "user_agents",
        "user_agents": "user_agents",
        "asn": "asn",
        "org": "org",
    }
    return mapping.get(t, t or "unknown")


@dataclass(frozen=True)
class EvidenceRef:
    evidence_path: str
    extracted_by: str
    record_id: Optional[str] = None
    field: Optional[str] = None
    preview: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "evidence_path": self.evidence_path,
            "extracted_by": self.extracted_by,
            "record_id": self.record_id,
            "field": self.field,
            "preview": self.preview,
        }


@dataclass
class EvidenceEvent:
    """A normalized DFIR event."""

    event_type: str
    timestamp: Optional[str]
    source: str
    extracted_by: str

    host: Optional[str] = None
    user: Optional[str] = None

    src_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    proto: Optional[str] = None

    domain: Optional[str] = None
    url: Optional[str] = None

    process: Optional[str] = None
    file_path: Optional[str] = None
    sha256: Optional[str] = None

    action: Optional[str] = None
    outcome: Optional[str] = None

    tags: List[str] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)

    event_id: str = field(default_factory=_next_event_id)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "timestamp": self.timestamp,
            "source": self.source,
            "extracted_by": self.extracted_by,
            "host": self.host,
            "user": self.user,
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "proto": self.proto,
            "domain": self.domain,
            "url": self.url,
            "process": self.process,
            "file_path": self.file_path,
            "sha256": self.sha256,
            "action": self.action,
            "outcome": self.outcome,
            "tags": self.tags,
            "raw": self.raw,
        }


@dataclass
class Indicator:
    """A normalized indicator with provenance and confidence."""

    indicator_type: str
    value: str
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    confidence: str = "medium"  # low/medium/high
    tags: List[str] = field(default_factory=list)
    sources: List[EvidenceRef] = field(default_factory=list)

    def key(self) -> tuple[str, str]:
        return (normalize_indicator_type(self.indicator_type), self.value)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": normalize_indicator_type(self.indicator_type),
            "value": self.value,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "confidence": self.confidence,
            "tags": self.tags,
            "sources": [s.to_dict() for s in self.sources],
        }


def merge_indicators(indicators: List[Indicator]) -> List[Indicator]:
    """Merge duplicates by (type,value); union sources/tags and expand seen window."""
    merged: Dict[tuple[str, str], Indicator] = {}

    def min_ts(a: Optional[str], b: Optional[str]) -> Optional[str]:
        if a is None:
            return b
        if b is None:
            return a
        return a if a <= b else b

    def max_ts(a: Optional[str], b: Optional[str]) -> Optional[str]:
        if a is None:
            return b
        if b is None:
            return a
        return a if a >= b else b

    # Maintain each merged indicator's set of source keys incrementally. The
    # previous code rebuilt this set from cur.sources on every merge, which is
    # O(n^2) when one value (e.g. a C2 domain) recurs across many log lines.
    seen_sources: Dict[tuple[str, str], set] = {}

    def _source_key(s) -> tuple:
        return (s.evidence_path, s.extracted_by, s.record_id, s.field)

    for ind in indicators:
        k = ind.key()
        if k not in merged:
            merged[k] = Indicator(
                indicator_type=normalize_indicator_type(ind.indicator_type),
                value=ind.value,
                first_seen=ind.first_seen,
                last_seen=ind.last_seen,
                confidence=ind.confidence,
                tags=list(ind.tags),
                sources=list(ind.sources),
            )
            seen_sources[k] = {_source_key(s) for s in merged[k].sources}
            continue

        cur = merged[k]
        cur.first_seen = min_ts(cur.first_seen, ind.first_seen)
        cur.last_seen = max_ts(cur.last_seen, ind.last_seen)
        if not set(ind.tags) <= set(cur.tags):
            cur.tags = sorted(set(cur.tags) | set(ind.tags))

        # Merge sources (best-effort de-dupe) using the persistent seen set.
        seen = seen_sources[k]
        for s in ind.sources:
            key = _source_key(s)
            if key in seen:
                continue
            cur.sources.append(s)
            seen.add(key)

        # Confidence: if either is high -> high; else if either medium -> medium
        order = {"low": 0, "medium": 1, "high": 2}
        cur.confidence = (
            "high"
            if order.get(cur.confidence, 1) >= 2 or order.get(ind.confidence, 1) >= 2
            else "medium"
            if order.get(cur.confidence, 1) >= 1 or order.get(ind.confidence, 1) >= 1
            else "low"
        )

    return list(merged.values())
