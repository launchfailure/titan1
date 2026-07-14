"""Versioned SQLite persistence for cross-case correlation."""

from __future__ import annotations

from contextlib import AbstractContextManager
import json
from pathlib import Path
import sqlite3
from typing import Iterable

from .models import AnalysisRecord

DATABASE_SCHEMA_VERSION = 1

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

CREATE INDEX IF NOT EXISTS idx_correlation_indicator_lookup
ON indicators(indicator_type, normalized_value);

CREATE INDEX IF NOT EXISTS idx_correlation_root_hash
ON analyses(root_hash);
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
            conn.execute("DELETE FROM indicators WHERE analysis_id = ?", (record.analysis_id,))
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
        row = self._conn().execute(
            "SELECT payload_json FROM analyses WHERE analysis_id = ?",
            (analysis_id,),
        ).fetchone()
        if row is None:
            return None
        return AnalysisRecord.from_dict(json.loads(str(row["payload_json"])))

    def iter_analyses(self, exclude_analysis_id: str | None = None) -> tuple[AnalysisRecord, ...]:
        if exclude_analysis_id is None:
            rows = self._conn().execute(
                "SELECT payload_json FROM analyses ORDER BY analysis_id"
            ).fetchall()
        else:
            rows = self._conn().execute(
                """
                SELECT payload_json FROM analyses
                WHERE analysis_id != ?
                ORDER BY analysis_id
                """,
                (exclude_analysis_id,),
            ).fetchall()
        return tuple(
            AnalysisRecord.from_dict(json.loads(str(row["payload_json"])))
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
                rows = self._conn().execute(
                    """
                    SELECT analysis_id FROM indicators
                    WHERE indicator_type = ? AND normalized_value = ?
                    ORDER BY analysis_id
                    """,
                    (indicator_type, normalized_value),
                ).fetchall()
            else:
                rows = self._conn().execute(
                    """
                    SELECT analysis_id FROM indicators
                    WHERE indicator_type = ? AND normalized_value = ?
                      AND analysis_id != ?
                    ORDER BY analysis_id
                    """,
                    (indicator_type, normalized_value, exclude_analysis_id),
                ).fetchall()
            matches.update(str(row["analysis_id"]) for row in rows)
        return tuple(sorted(matches))

    def schema_version(self) -> int:
        row = self._conn().execute(
            "SELECT value FROM correlation_meta WHERE key = 'schema_version'"
        ).fetchone()
        if row is None:
            raise RuntimeError("correlation database schema version is missing")
        return int(row["value"])
