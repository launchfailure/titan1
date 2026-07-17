"""Versioned SQLite persistence for cross-case correlation."""

from __future__ import annotations

from contextlib import AbstractContextManager
import json
from pathlib import Path
import sqlite3
from typing import TYPE_CHECKING, Iterable

from .models import AnalysisRecord

if TYPE_CHECKING:  # pragma: no cover - import cycle guard for annotations
    from .payload_similarity import PayloadFingerprint
    from .timeline import TimelineEvent

DATABASE_SCHEMA_VERSION = 2

# Deterministic cap on persisted timeline events per analysis. Evidence files
# can carry very large event sets; storing them unbounded would make the
# correlation database a decompression-bomb amplifier. Events are sorted
# before truncation so the retained subset is stable across runs.
MAX_TIMELINE_EVENTS_PER_ANALYSIS = 2000

_SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS correlation_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS analyses (
    analysis_id TEXT PRIMARY KEY,
    root_hash TEXT NOT NULL,
    created_at TEXT,
    payload_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS indicators (
    indicator_id TEXT NOT NULL,
    analysis_id TEXT NOT NULL,
    indicator_type TEXT NOT NULL,
    normalized_value TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    PRIMARY KEY (analysis_id, indicator_id),
    FOREIGN KEY (analysis_id) REFERENCES analyses(analysis_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS payload_fingerprints (
    analysis_id TEXT PRIMARY KEY,
    payload_json TEXT NOT NULL,
    FOREIGN KEY (analysis_id) REFERENCES analyses(analysis_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS timeline_events (
    analysis_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    PRIMARY KEY (analysis_id, event_id),
    FOREIGN KEY (analysis_id) REFERENCES analyses(analysis_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_correlation_indicator_lookup
ON indicators(indicator_type, normalized_value);

CREATE INDEX IF NOT EXISTS idx_correlation_root_hash
ON analyses(root_hash);

CREATE INDEX IF NOT EXISTS idx_correlation_timeline_timestamp
ON timeline_events(timestamp);
"""


class CorrelationDatabase(AbstractContextManager["CorrelationDatabase"]):
    """Small offline database with deterministic upsert and query behavior."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.connection: sqlite3.Connection | None = None

    def open(self) -> "CorrelationDatabase":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(str(self.path))
        self.connection.row_factory = sqlite3.Row
        self.connection.executescript(_SCHEMA)
        self.connection.execute(
            "INSERT OR REPLACE INTO correlation_meta(key, value) VALUES (?, ?)",
            ("schema_version", str(DATABASE_SCHEMA_VERSION)),
        )
        self.connection.commit()
        return self

    def close(self) -> None:
        if self.connection is not None:
            self.connection.commit()
            self.connection.close()
            self.connection = None

    def __enter__(self) -> "CorrelationDatabase":
        return self.open()

    def __exit__(self, exc_type, exc, tb) -> None:
        if self.connection is not None:
            if exc_type is None:
                self.connection.commit()
            else:
                self.connection.rollback()
        self.close()

    def _conn(self) -> sqlite3.Connection:
        if self.connection is None:
            raise RuntimeError("correlation database is not open")
        return self.connection

    def record_analysis(self, record: AnalysisRecord) -> None:
        conn = self._conn()
        payload = json.dumps(record.to_dict(), sort_keys=True, separators=(",", ":"))

        with conn:
            conn.execute(
                """
                INSERT INTO analyses(analysis_id, root_hash, created_at, payload_json)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(analysis_id) DO UPDATE SET
                    root_hash=excluded.root_hash,
                    created_at=excluded.created_at,
                    payload_json=excluded.payload_json
                """,
                (record.analysis_id, record.root_hash, record.created_at, payload),
            )
            conn.execute(
                "DELETE FROM indicators WHERE analysis_id = ?", (record.analysis_id,)
            )
            conn.executemany(
                """
                INSERT INTO indicators(
                    indicator_id, analysis_id, indicator_type,
                    normalized_value, payload_json
                ) VALUES (?, ?, ?, ?, ?)
                """,
                [
                    (
                        indicator.indicator_id,
                        record.analysis_id,
                        indicator.indicator_type,
                        indicator.normalized_value,
                        json.dumps(
                            indicator.to_dict(),
                            sort_keys=True,
                            separators=(",", ":"),
                        ),
                    )
                    for indicator in record.indicators
                ],
            )

    def get_analysis(self, analysis_id: str) -> AnalysisRecord | None:
        row = (
            self._conn()
            .execute(
                "SELECT payload_json FROM analyses WHERE analysis_id = ?",
                (analysis_id,),
            )
            .fetchone()
        )
        if row is None:
            return None
        return AnalysisRecord.from_dict(json.loads(str(row["payload_json"])))

    def iter_analyses(
        self, exclude_analysis_id: str | None = None
    ) -> tuple[AnalysisRecord, ...]:
        if exclude_analysis_id is None:
            rows = (
                self._conn()
                .execute("SELECT payload_json FROM analyses ORDER BY analysis_id")
                .fetchall()
            )
        else:
            rows = (
                self._conn()
                .execute(
                    """
                SELECT payload_json FROM analyses
                WHERE analysis_id != ?
                ORDER BY analysis_id
                """,
                    (exclude_analysis_id,),
                )
                .fetchall()
            )
        return tuple(
            AnalysisRecord.from_dict(json.loads(str(row["payload_json"])))
            for row in rows
        )

    def record_fingerprint(self, fingerprint: "PayloadFingerprint") -> None:
        """Persist one analysis' payload fingerprint (upsert)."""

        conn = self._conn()
        with conn:
            conn.execute(
                """
                INSERT INTO payload_fingerprints(analysis_id, payload_json)
                VALUES (?, ?)
                ON CONFLICT(analysis_id) DO UPDATE SET
                    payload_json=excluded.payload_json
                """,
                (
                    fingerprint.analysis_id,
                    json.dumps(
                        fingerprint.to_dict(), sort_keys=True, separators=(",", ":")
                    ),
                ),
            )

    def iter_fingerprints(self) -> tuple["PayloadFingerprint", ...]:
        from .payload_similarity import PayloadFingerprint

        rows = (
            self._conn()
            .execute(
                "SELECT payload_json FROM payload_fingerprints ORDER BY analysis_id"
            )
            .fetchall()
        )
        return tuple(
            PayloadFingerprint.from_dict(json.loads(str(row["payload_json"])))
            for row in rows
        )

    def record_timeline_events(
        self, analysis_id: str, events: Iterable["TimelineEvent"]
    ) -> None:
        """Replace the persisted timeline events for one analysis.

        Events are sorted before the deterministic per-analysis cap is
        applied, so re-recording the same analysis always retains the same
        subset.
        """

        from .timeline import sort_timeline

        ordered = sort_timeline(
            event for event in events if event.analysis_id == analysis_id
        )[:MAX_TIMELINE_EVENTS_PER_ANALYSIS]
        conn = self._conn()
        with conn:
            conn.execute(
                "DELETE FROM timeline_events WHERE analysis_id = ?", (analysis_id,)
            )
            conn.executemany(
                """
                INSERT OR REPLACE INTO timeline_events(
                    analysis_id, event_id, timestamp, payload_json
                ) VALUES (?, ?, ?, ?)
                """,
                [
                    (
                        analysis_id,
                        event.event_id,
                        event.timestamp,
                        json.dumps(
                            event.to_dict(), sort_keys=True, separators=(",", ":")
                        ),
                    )
                    for event in ordered
                ],
            )

    def iter_timeline_events(self) -> tuple["TimelineEvent", ...]:
        from .timeline import TimelineEvent

        rows = (
            self._conn()
            .execute(
                "SELECT payload_json FROM timeline_events ORDER BY timestamp, event_id"
            )
            .fetchall()
        )
        return tuple(
            TimelineEvent.from_dict(json.loads(str(row["payload_json"])))
            for row in rows
        )

    def search_indicators(
        self, value: str, indicator_type: str | None = None
    ) -> tuple[dict, ...]:
        """Search recorded indicators by exact normalized value.

        Returns one entry per (analysis, indicator) match, each carrying the
        stored indicator payload with its evidence references. Matching is
        case-insensitive on the value; ``indicator_type`` (when given)
        restricts the search to one indicator type.
        """

        query = """
            SELECT analysis_id, indicator_type, payload_json FROM indicators
            WHERE normalized_value = ? COLLATE NOCASE
        """
        params: list[str] = [value]
        if indicator_type is not None:
            query += " AND indicator_type = ?"
            params.append(indicator_type.strip().lower())
        query += " ORDER BY analysis_id, indicator_type, indicator_id"
        rows = self._conn().execute(query, params).fetchall()
        return tuple(
            {
                "analysis_id": str(row["analysis_id"]),
                "indicator_type": str(row["indicator_type"]),
                "indicator": json.loads(str(row["payload_json"])),
            }
            for row in rows
        )

    def analyses_for_indicators(
        self,
        indicators: Iterable[tuple[str, str]],
        exclude_analysis_id: str | None = None,
    ) -> tuple[str, ...]:
        matches: set[str] = set()
        for indicator_type, normalized_value in sorted(set(indicators)):
            if exclude_analysis_id is None:
                rows = (
                    self._conn()
                    .execute(
                        """
                    SELECT analysis_id FROM indicators
                    WHERE indicator_type = ? AND normalized_value = ?
                    ORDER BY analysis_id
                    """,
                        (indicator_type, normalized_value),
                    )
                    .fetchall()
                )
            else:
                rows = (
                    self._conn()
                    .execute(
                        """
                    SELECT analysis_id FROM indicators
                    WHERE indicator_type = ? AND normalized_value = ?
                      AND analysis_id != ?
                    ORDER BY analysis_id
                    """,
                        (indicator_type, normalized_value, exclude_analysis_id),
                    )
                    .fetchall()
                )
            matches.update(str(row["analysis_id"]) for row in rows)
        return tuple(sorted(matches))

    def schema_version(self) -> int:
        row = (
            self._conn()
            .execute("SELECT value FROM correlation_meta WHERE key = 'schema_version'")
            .fetchone()
        )
        if row is None:
            raise RuntimeError("correlation database schema version is missing")
        return int(row["value"])
