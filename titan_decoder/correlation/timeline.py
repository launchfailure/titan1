"""Timeline normalization for cross-case correlation."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

from .models import stable_id


def normalize_timestamp(value: str | datetime) -> str:
    """Normalize a timestamp to an RFC 3339 UTC string."""

    if isinstance(value, datetime):
        parsed = value
    else:
        text = value.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        parsed = datetime.fromisoformat(text)

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    parsed = parsed.astimezone(timezone.utc)
    return parsed.isoformat(timespec="microseconds").replace("+00:00", "Z")


@dataclass(frozen=True)
class TimelineEvent:
    """Stable, sortable event from one analysis."""

    analysis_id: str
    timestamp: str
    kind: str
    summary: str
    source_id: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.analysis_id or not self.kind or not self.summary:
            raise ValueError("analysis_id, kind, and summary are required")
        object.__setattr__(self, "timestamp", normalize_timestamp(self.timestamp))
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def event_id(self) -> str:
        return stable_id(
            "timeline-event",
            {
                "analysis_id": self.analysis_id,
                "timestamp": self.timestamp,
                "kind": self.kind,
                "summary": self.summary,
                "source_id": self.source_id,
            },
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "analysis_id": self.analysis_id,
            "timestamp": self.timestamp,
            "kind": self.kind,
            "summary": self.summary,
            "source_id": self.source_id,
            "metadata": dict(self.metadata),
        }


def sort_timeline(events: Iterable[TimelineEvent]) -> tuple[TimelineEvent, ...]:
    """Return events in deterministic chronological order."""

    return tuple(sorted(events, key=lambda event: (event.timestamp, event.event_id)))
