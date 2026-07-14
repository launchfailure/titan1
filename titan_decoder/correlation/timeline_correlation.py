"""Cross-case timeline correlation.

Links events from *different* analyses that fall within a configurable time
window and either share observable metadata values (domain, IP, hash, …) or
are the same kind of event. Scores are deterministic: a fixed semantic
component plus temporal proximity.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Iterable

from .models import stable_id
from .timeline import TimelineEvent, sort_timeline

SCHEMA_VERSION = "timeline-correlation-v1.0"


@dataclass(frozen=True)
class TimelineLink:
    """One deterministic link between events from two analyses."""

    left_event_id: str
    right_event_id: str
    delta_seconds: float
    reason: str
    score: float

    @property
    def link_id(self) -> str:
        return stable_id(
            "timeline-link",
            {
                "left": self.left_event_id,
                "right": self.right_event_id,
                "reason": self.reason,
            },
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "link_id": self.link_id,
            "left_event_id": self.left_event_id,
            "right_event_id": self.right_event_id,
            "delta_seconds": round(self.delta_seconds, 6),
            "reason": self.reason,
            "score": round(self.score, 6),
        }


def _comparable_values(event: TimelineEvent) -> set[str]:
    """Metadata values that are safe to compare across analyses."""

    return {
        str(value)
        for value in event.metadata.values()
        if isinstance(value, (str, int, float)) and str(value)
    }


def _parse(timestamp: str) -> datetime:
    return datetime.fromisoformat(timestamp.replace("Z", "+00:00"))


def correlate_timelines(
    events: Iterable[TimelineEvent],
    *,
    window_seconds: float = 300.0,
) -> dict[str, Any]:
    """Correlate normalized events across analyses.

    Only pairs from different analyses within ``window_seconds`` of each
    other are considered. Shared observable metadata is required for a
    strong link; matching event kinds alone produce a weaker one.
    """

    if window_seconds < 0:
        raise ValueError("window_seconds must be non-negative")

    ordered = sort_timeline(events)
    links: list[TimelineLink] = []
    for index, left in enumerate(ordered):
        left_time = _parse(left.timestamp)
        left_values = _comparable_values(left)
        for right in ordered[index + 1:]:
            if left.analysis_id == right.analysis_id:
                continue
            delta = abs((_parse(right.timestamp) - left_time).total_seconds())
            if delta > window_seconds:
                # Events are sorted chronologically, so once one falls
                # outside the window every later one does too.
                break
            shared = sorted(left_values & _comparable_values(right))
            if not shared and left.kind != right.kind:
                continue
            reason = (
                "shared_metadata:" + ",".join(shared[:5])
                if shared
                else "same_event_kind"
            )
            proximity = 1.0 if window_seconds == 0 else max(0.0, 1.0 - delta / window_seconds)
            semantic = 1.0 if shared else 0.5
            links.append(
                TimelineLink(
                    left_event_id=left.event_id,
                    right_event_id=right.event_id,
                    delta_seconds=delta,
                    reason=reason,
                    score=min(1.0, 0.65 * semantic + 0.35 * proximity),
                )
            )

    links.sort(key=lambda link: (-link.score, link.delta_seconds, link.link_id))
    return {
        "schema_version": SCHEMA_VERSION,
        "event_count": len(ordered),
        "link_count": len(links),
        "links": [link.to_dict() for link in links],
    }
