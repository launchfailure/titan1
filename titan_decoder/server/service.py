"""Persistent artifact store, hash-deduplicated queue, and analysis workers."""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from titan_decoder.config import Config
from titan_decoder.core.engine import TitanEngine
from titan_decoder.utils.helpers import sha256


class ArtifactStore:
    """Hash-addressed artifacts and reports with atomic publication."""

    def __init__(self, root: Path, max_artifact_bytes: int = 50 * 1024 * 1024):
        self.root = Path(root)
        self.max_artifact_bytes = max_artifact_bytes
        self.blobs = self.root / "blobs"
        self.reports = self.root / "reports"
        self.blobs.mkdir(parents=True, exist_ok=True)
        self.reports.mkdir(parents=True, exist_ok=True)

    def _blob_path(self, digest: str) -> Path:
        return self.blobs / digest[:2] / digest

    def put(self, data: bytes) -> tuple[str, bool]:
        if not data:
            raise ValueError("artifact must not be empty")
        if len(data) > self.max_artifact_bytes:
            raise ValueError("artifact exceeds configured size limit")
        digest = sha256(data)
        target = self._blob_path(digest)
        if target.exists():
            return digest, False
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_name(
            f".{target.name}.{os.getpid()}.{threading.get_ident()}"
        )
        try:
            with temporary.open("xb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            try:
                os.replace(temporary, target)
            except FileExistsError:
                temporary.unlink(missing_ok=True)
        finally:
            temporary.unlink(missing_ok=True)
        return digest, True

    def get(self, digest: str) -> bytes:
        return self._blob_path(digest).read_bytes()

    def put_report(self, digest: str, report: dict[str, Any]) -> None:
        target = self.reports / f"{digest}.json"
        temporary = target.with_suffix(f".{os.getpid()}.{threading.get_ident()}.tmp")
        payload = json.dumps(report, sort_keys=True, separators=(",", ":")).encode()
        try:
            with temporary.open("xb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, target)
        finally:
            temporary.unlink(missing_ok=True)

    def get_report(self, digest: str) -> dict[str, Any]:
        return json.loads((self.reports / f"{digest}.json").read_text(encoding="utf-8"))


class JobQueue:
    """SQLite-backed queue whose job identity is the artifact SHA-256."""

    def __init__(self, path: Path, lease_timeout_seconds: int = 900):
        self.path = Path(path)
        self.lease_timeout_seconds = max(60, lease_timeout_seconds)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=30000")
        connection.execute("PRAGMA journal_mode=WAL")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """CREATE TABLE IF NOT EXISTS jobs (
                    id TEXT PRIMARY KEY,
                    state TEXT NOT NULL CHECK (state IN ('queued','running','completed','failed')),
                    created REAL NOT NULL,
                    updated REAL NOT NULL,
                    worker TEXT,
                    error TEXT
                )"""
            )

    def enqueue(self, digest: str) -> tuple[dict[str, Any], bool]:
        now = time.time()
        with self._connect() as connection:
            cursor = connection.execute(
                "INSERT OR IGNORE INTO jobs(id,state,created,updated) VALUES(?, 'queued', ?, ?)",
                (digest, now, now),
            )
            created = cursor.rowcount == 1
            if not created:
                cursor = connection.execute(
                    "UPDATE jobs SET state='queued', worker=NULL, error=NULL, updated=? "
                    "WHERE id=? AND state='failed'",
                    (now, digest),
                )
                created = cursor.rowcount == 1
        return self.get(digest), created

    def get(self, job_id: str) -> dict[str, Any]:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM jobs WHERE id = ?", (job_id,)
            ).fetchone()
        if row is None:
            raise KeyError(job_id)
        return dict(row)

    def lease(self, worker: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            now = time.time()
            connection.execute(
                "UPDATE jobs SET state='queued', worker=NULL, updated=? "
                "WHERE state='running' AND updated < ?",
                (now, now - self.lease_timeout_seconds),
            )
            row = connection.execute(
                "SELECT id FROM jobs WHERE state = 'queued' ORDER BY created, id LIMIT 1"
            ).fetchone()
            if row is None:
                connection.execute("COMMIT")
                return None
            connection.execute(
                "UPDATE jobs SET state='running', worker=?, updated=? WHERE id=? AND state='queued'",
                (worker, now, row["id"]),
            )
            connection.execute("COMMIT")
        return self.get(row["id"])

    def complete(self, job_id: str) -> None:
        self._finish(job_id, "completed", None)

    def fail(self, job_id: str, error: str) -> None:
        self._finish(job_id, "failed", error[:4096])

    def _finish(self, job_id: str, state: str, error: str | None) -> None:
        with self._connect() as connection:
            cursor = connection.execute(
                "UPDATE jobs SET state=?, error=?, updated=? WHERE id=? AND state='running'",
                (state, error, time.time(), job_id),
            )
            if cursor.rowcount != 1:
                raise RuntimeError("job is not leased")


class TitanService:
    """Coordinates submission, persistent workers, and report retrieval."""

    def __init__(
        self,
        root: Path,
        config: Config | None = None,
        max_artifact_bytes: int = 50 * 1024 * 1024,
    ):
        self.store = ArtifactStore(Path(root), max_artifact_bytes)
        self.queue = JobQueue(Path(root) / "queue.sqlite3")
        self.config = config or Config()

    def submit(self, data: bytes) -> tuple[dict[str, Any], bool]:
        digest, _stored = self.store.put(data)
        return self.queue.enqueue(digest)

    def work_once(self, worker: str) -> dict[str, Any] | None:
        job = self.queue.lease(worker)
        if job is None:
            return None
        try:
            report = TitanEngine(self.config).run_analysis(self.store.get(job["id"]))
            self.store.put_report(job["id"], report)
            self.queue.complete(job["id"])
        except Exception as error:
            self.queue.fail(job["id"], f"{type(error).__name__}: {error}")
        return self.queue.get(job["id"])
