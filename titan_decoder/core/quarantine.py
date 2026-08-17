"""Hash-addressed, recoverable quarantine storage.

Quarantine defaults to copying evidence into an immutable local vault. Moving
the original is an explicit caller decision, and restoration always verifies
the stored SHA-256 before writing any bytes back out.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile
import uuid
from typing import Any


_RECORD_ID = re.compile(r"^[0-9a-f]{32}$")


def _hash_file(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass(frozen=True)
class QuarantineRecord:
    id: str
    sha256: str
    source_path: str
    original_name: str
    size: int
    verdict: str
    quarantined_at: str
    object_path: str
    requested_action: str
    source_removed: bool
    report_path: str | None = None
    warning: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class QuarantineVault:
    """Store evidence objects and restoration metadata under one local root."""

    def __init__(self, root: Path | None = None):
        self.root = (root or Path.home() / ".titan_decoder" / "quarantine").expanduser()
        self.objects = self.root / "objects"
        self.records_dir = self.root / "records"

    def quarantine(
        self,
        source: Path,
        verdict: str,
        *,
        report_path: Path | None = None,
        move: bool = False,
    ) -> QuarantineRecord:
        source = source.expanduser().resolve()
        if not source.is_file() or source.is_symlink():
            raise ValueError("only regular, non-symlink files can be quarantined")
        verdict = str(verdict).upper()
        if verdict not in {"MALICIOUS", "SUSPICIOUS"}:
            raise ValueError("quarantine requires a MALICIOUS or SUSPICIOUS verdict")
        digest = _hash_file(source)
        size = source.stat().st_size
        self.objects.mkdir(parents=True, exist_ok=True)
        self.records_dir.mkdir(parents=True, exist_ok=True)
        object_path = self.objects / digest
        if object_path.exists():
            if not object_path.is_file() or _hash_file(object_path) != digest:
                raise RuntimeError(
                    "existing quarantine object failed SHA-256 verification"
                )
        else:
            self._copy_verified(source, object_path, digest, read_only=True)
        size = object_path.stat().st_size

        record_id = uuid.uuid4().hex
        source_removed = False
        warning = None
        quarantined_at = datetime.now(timezone.utc).isoformat()
        record = QuarantineRecord(
            id=record_id,
            sha256=digest,
            source_path=str(source),
            original_name=source.name,
            size=size,
            verdict=verdict,
            quarantined_at=quarantined_at,
            object_path=str(object_path),
            requested_action="move" if move else "copy",
            source_removed=False,
            report_path=str(report_path) if report_path else None,
            warning=None,
        )
        # A recoverable record must exist before a requested move removes the source.
        self._write_record(record)
        if move:
            try:
                source.unlink()
                source_removed = True
            except OSError as exc:
                warning = f"vault copy completed but source removal failed: {exc}"
            record = QuarantineRecord(
                id=record_id,
                sha256=digest,
                source_path=str(source),
                original_name=source.name,
                size=size,
                verdict=verdict,
                quarantined_at=quarantined_at,
                object_path=str(object_path),
                requested_action="move",
                source_removed=source_removed,
                report_path=str(report_path) if report_path else None,
                warning=warning,
            )
            self._write_record(record)
        return record

    def records(self) -> list[QuarantineRecord]:
        if not self.records_dir.is_dir():
            return []
        values: list[QuarantineRecord] = []
        for path in sorted(self.records_dir.glob("*.json")):
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
                values.append(QuarantineRecord(**value))
            except (OSError, TypeError, ValueError, json.JSONDecodeError):
                continue
        return sorted(values, key=lambda value: value.quarantined_at, reverse=True)

    def get(self, record_id: str) -> QuarantineRecord:
        if not _RECORD_ID.fullmatch(record_id):
            raise ValueError("invalid quarantine record id")
        path = self.records_dir / f"{record_id}.json"
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            return QuarantineRecord(**value)
        except FileNotFoundError as exc:
            raise KeyError(f"unknown quarantine record: {record_id}") from exc

    def restore(
        self,
        record_id: str,
        destination: Path | None = None,
        *,
        overwrite: bool = False,
    ) -> Path:
        record = self.get(record_id)
        object_path = Path(record.object_path)
        if not object_path.is_file() or _hash_file(object_path) != record.sha256:
            raise RuntimeError(
                "quarantine object is missing or failed hash verification"
            )
        destination = (
            destination.expanduser()
            if destination is not None
            else Path(record.source_path)
        )
        destination = destination.resolve()
        if destination.exists() and not overwrite:
            raise FileExistsError(
                f"restore destination already exists: {destination}; choose another path"
            )
        destination.parent.mkdir(parents=True, exist_ok=True)
        self._copy_verified(
            object_path,
            destination,
            record.sha256,
            overwrite=overwrite,
            read_only=False,
        )
        return destination

    @staticmethod
    def _copy_verified(
        source: Path,
        destination: Path,
        expected_sha256: str,
        *,
        overwrite: bool = False,
        read_only: bool = False,
    ) -> None:
        if not overwrite:
            # Publish through O_EXCL. On Windows, security software can remove
            # hidden NamedTemporaryFile payloads between close and verification;
            # that made quarantine intermittently fail under a full scan. The
            # exclusive descriptor retains no-overwrite semantics, and any
            # interrupted or hash-mismatched destination is removed below.
            try:
                descriptor = os.open(
                    destination,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                )
            except FileExistsError as exc:
                raise FileExistsError(
                    f"destination already exists: {destination}"
                ) from exc
            try:
                with os.fdopen(descriptor, "wb") as output_handle:
                    with source.open("rb") as input_handle:
                        shutil.copyfileobj(
                            input_handle, output_handle, length=1024 * 1024
                        )
                    output_handle.flush()
                    os.fsync(output_handle.fileno())
                if _hash_file(destination) != expected_sha256:
                    raise RuntimeError("destination failed post-copy hash verification")
                if read_only:
                    try:
                        destination.chmod(stat.S_IREAD)
                    except OSError:
                        pass
                return
            except Exception:
                destination.unlink(missing_ok=True)
                raise

        with tempfile.NamedTemporaryFile(
            "wb",
            dir=destination.parent,
            prefix=f".{destination.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            with source.open("rb") as source_handle:
                shutil.copyfileobj(source_handle, handle, length=1024 * 1024)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            if _hash_file(temporary) != expected_sha256:
                raise RuntimeError("quarantine copy failed hash verification")
            temporary.replace(destination)
            if read_only:
                try:
                    destination.chmod(stat.S_IREAD)
                except OSError:
                    pass
        finally:
            if temporary.exists():
                temporary.unlink()

    def _write_record(self, record: QuarantineRecord) -> None:
        destination = self.records_dir / f"{record.id}.json"
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=self.records_dir,
            prefix=f".{record.id}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            json.dump(record.to_dict(), handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
            temporary = Path(handle.name)
        try:
            temporary.replace(destination)
        finally:
            if temporary.exists():
                temporary.unlink()
