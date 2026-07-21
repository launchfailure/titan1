"""Persistent local sample history for the native Titan workbench."""

from __future__ import annotations

import base64
from dataclasses import asdict, dataclass, fields
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import tempfile
import uuid
from typing import Any

from titan_decoder.workbench_ui.models import AnalysisSnapshot


@dataclass(frozen=True)
class SampleRecord:
    id: str
    name: str
    size: int
    created_at: str
    sha256: str | None = None
    evidence_file: str | None = None
    snapshot_file: str | None = None
    source_path: str | None = None
    visible_in_latest: bool = True

    @property
    def analyzed_label(self) -> str:
        try:
            value = datetime.fromisoformat(self.created_at)
            return value.astimezone().strftime("%Y-%m-%d  %H:%M:%S")
        except ValueError:
            return self.created_at


class SampleArchive:
    """Content-addressed evidence storage with independently hideable history."""

    VERSION = 1

    def __init__(self, root: Path | None = None):
        self.root = root or Path.home() / ".titan_decoder" / "sample_history"
        self.objects_dir = self.root / "objects"
        self.snapshots_dir = self.root / "snapshots"
        self.index_path = self.root / "index.json"
        self.objects_dir.mkdir(parents=True, exist_ok=True)
        self.snapshots_dir.mkdir(parents=True, exist_ok=True)

    def _read_payload(self) -> dict[str, Any]:
        if not self.index_path.exists():
            return {"version": self.VERSION, "samples": [], "migrated_sources": []}
        try:
            value = json.loads(self.index_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {"version": self.VERSION, "samples": [], "migrated_sources": []}
        if not isinstance(value, dict) or not isinstance(value.get("samples"), list):
            return {"version": self.VERSION, "samples": [], "migrated_sources": []}
        if not isinstance(value.get("migrated_sources"), list):
            value["migrated_sources"] = [
                str(item["source_path"])
                for item in value["samples"]
                if isinstance(item, dict)
                and item.get("source_path")
                and item.get("evidence_file") is None
            ]
        return value

    def _write_payload(self, payload: dict[str, Any]) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        temporary: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                "w",
                encoding="utf-8",
                dir=self.root,
                prefix=".index.",
                suffix=".tmp",
                delete=False,
            ) as handle:
                temporary = Path(handle.name)
                json.dump(payload, handle, indent=2)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.index_path)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)

    @staticmethod
    def _record(value: dict[str, Any]) -> SampleRecord:
        allowed = {item.name for item in fields(SampleRecord)}
        return SampleRecord(
            **{key: value for key, value in value.items() if key in allowed}
        )

    def records(self, *, include_hidden: bool = True) -> list[SampleRecord]:
        values = [
            self._record(item)
            for item in self._read_payload()["samples"]
            if isinstance(item, dict)
        ]
        if not include_hidden:
            values = [item for item in values if item.visible_in_latest]
        return sorted(values, key=lambda item: item.created_at, reverse=True)

    def get(self, sample_id: str) -> SampleRecord | None:
        return next((item for item in self.records() if item.id == sample_id), None)

    def archive_bytes(
        self,
        data: bytes,
        name: str,
        *,
        source_path: str | None = None,
    ) -> SampleRecord:
        digest = sha256(data).hexdigest()
        object_path = self.objects_dir / f"{digest}.bin"
        if not object_path.exists():
            temporary: Path | None = None
            try:
                with tempfile.NamedTemporaryFile(
                    "wb",
                    dir=self.objects_dir,
                    prefix=f".{digest}.",
                    suffix=".tmp",
                    delete=False,
                ) as handle:
                    temporary = Path(handle.name)
                    handle.write(data)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temporary, object_path)
            finally:
                if temporary is not None:
                    temporary.unlink(missing_ok=True)

        record = SampleRecord(
            id=uuid.uuid4().hex,
            name=Path(name).name or "sample.bin",
            size=len(data),
            created_at=datetime.now(timezone.utc).isoformat(),
            sha256=digest,
            evidence_file=object_path.name,
            source_path=source_path,
        )
        payload = self._read_payload()
        payload["samples"].append(asdict(record))
        self._write_payload(payload)
        return record

    def import_snapshot(
        self,
        snapshot: AnalysisSnapshot,
        *,
        source_path: str | None = None,
    ) -> SampleRecord | None:
        payload = self._read_payload()
        if source_path:
            existing = next(
                (
                    self._record(item)
                    for item in payload["samples"]
                    if isinstance(item, dict)
                    and item.get("source_path") == source_path
                    and item.get("evidence_file") is None
                ),
                None,
            )
            if existing is not None:
                return existing
            if source_path in payload["migrated_sources"]:
                return None
        record = SampleRecord(
            id=uuid.uuid4().hex,
            name=Path(snapshot.source_name).name or "analysis.json",
            size=snapshot.source_size,
            created_at=datetime.now(timezone.utc).isoformat(),
            source_path=source_path,
        )
        payload["samples"].append(asdict(record))
        if source_path:
            payload["migrated_sources"].append(source_path)
        self._write_payload(payload)
        self.attach_snapshot(record.id, snapshot)
        return self.get(record.id) or record

    @staticmethod
    def _snapshot_payload(snapshot: AnalysisSnapshot) -> dict[str, Any]:
        payload = asdict(snapshot)
        decoded = payload.get("decoded_output")
        if isinstance(decoded, bytes):
            payload["decoded_output_base64"] = base64.b64encode(decoded).decode("ascii")
            payload["decoded_output"] = None
        payload["batch_errors"] = list(snapshot.batch_errors)
        return payload

    def attach_snapshot(self, sample_id: str, snapshot: AnalysisSnapshot) -> None:
        payload = self._read_payload()
        snapshot_name = f"{sample_id}.json"
        destination = self.snapshots_dir / snapshot_name
        destination.write_text(
            json.dumps(self._snapshot_payload(snapshot), indent=2),
            encoding="utf-8",
        )
        for item in payload["samples"]:
            if isinstance(item, dict) and item.get("id") == sample_id:
                item["snapshot_file"] = snapshot_name
                item["name"] = Path(snapshot.source_name).name or item.get("name")
                item["size"] = snapshot.source_size
                break
        self._write_payload(payload)

    def load_snapshot(self, sample_id: str) -> AnalysisSnapshot | None:
        record = self.get(sample_id)
        if record is None or not record.snapshot_file:
            return None
        path = self.snapshots_dir / Path(record.snapshot_file).name
        if not path.is_file():
            return None
        payload = json.loads(path.read_text(encoding="utf-8"))
        decoded = payload.pop("decoded_output_base64", None)
        if decoded is not None:
            payload["decoded_output"] = base64.b64decode(decoded)
        payload["batch_errors"] = tuple(payload.get("batch_errors") or ())
        allowed = {item.name for item in fields(AnalysisSnapshot)}
        return AnalysisSnapshot(
            **{key: value for key, value in payload.items() if key in allowed}
        )

    def load_evidence(self, sample_id: str) -> bytes | None:
        record = self.get(sample_id)
        if record is None or not record.evidence_file:
            return None
        path = self.objects_dir / Path(record.evidence_file).name
        return path.read_bytes() if path.is_file() else None

    def set_latest_visibility(self, sample_id: str, visible: bool) -> None:
        payload = self._read_payload()
        for item in payload["samples"]:
            if isinstance(item, dict) and item.get("id") == sample_id:
                item["visible_in_latest"] = visible
                break
        self._write_payload(payload)

    def delete_permanently(self, sample_id: str) -> None:
        payload = self._read_payload()
        removed = next(
            (
                item
                for item in payload["samples"]
                if isinstance(item, dict) and item.get("id") == sample_id
            ),
            None,
        )
        if removed is None:
            return
        payload["samples"] = [
            item
            for item in payload["samples"]
            if not isinstance(item, dict) or item.get("id") != sample_id
        ]
        self._write_payload(payload)
        snapshot_name = removed.get("snapshot_file")
        if snapshot_name:
            (self.snapshots_dir / Path(str(snapshot_name)).name).unlink(missing_ok=True)
        evidence_name = removed.get("evidence_file")
        if evidence_name and not any(
            isinstance(item, dict) and item.get("evidence_file") == evidence_name
            for item in payload["samples"]
        ):
            (self.objects_dir / Path(str(evidence_name)).name).unlink(missing_ok=True)

    def save_copy(self, sample_id: str, destination: Path) -> Path:
        record = self.get(sample_id)
        if record is None:
            raise ValueError("The selected archived sample no longer exists.")
        destination.parent.mkdir(parents=True, exist_ok=True)
        if record.evidence_file:
            source = self.objects_dir / Path(record.evidence_file).name
            if source.is_file():
                shutil.copyfile(source, destination)
                return destination
        snapshot = self.load_snapshot(sample_id)
        if snapshot is None:
            raise ValueError("The selected sample has no evidence or saved analysis.")
        destination.write_text(json.dumps(snapshot.report, indent=2), encoding="utf-8")
        return destination
