"""Persistent investigation workspaces.

A workspace records which reports belong to an investigation plus analyst
annotations (per-report tags, notes, and status, and workspace-level notes).
It stores report *paths*, never report contents — original reports remain
unchanged. The on-disk contract is versioned as ``analyst-workspace-v1.0``
(``schemas/analyst-workspace-v1.0.schema.json``).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json
from pathlib import Path
from typing import Any

WORKSPACE_SCHEMA_VERSION = "analyst-workspace-v1.0"

CASE_STATUSES = ("open", "in-progress", "closed")


@dataclass
class CaseEntry:
    """One report tracked by an investigation."""

    report_path: str
    tags: list[str] = field(default_factory=list)
    note: str = ""
    status: str = "open"

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CaseEntry":
        # Tolerant: unknown keys from newer schema versions are ignored
        # instead of crashing the load.
        return cls(
            report_path=str(data.get("report_path") or ""),
            tags=[str(tag) for tag in data.get("tags") or []],
            note=str(data.get("note") or ""),
            status=str(data.get("status") or "open"),
        )


@dataclass
class InvestigationWorkspace:
    """A named investigation over a set of reports."""

    name: str
    entries: list[CaseEntry] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    version: str = "1.0"

    def add_report(self, report_path: str | Path) -> CaseEntry:
        normalized = str(Path(report_path).resolve())
        for item in self.entries:
            if item.report_path == normalized:
                return item
        entry = CaseEntry(normalized)
        self.entries.append(entry)
        self.entries.sort(key=lambda item: item.report_path)
        return entry

    def remove_report(self, report_path: str | Path) -> bool:
        normalized = str(Path(report_path).resolve())
        before = len(self.entries)
        self.entries = [item for item in self.entries if item.report_path != normalized]
        return len(self.entries) != before

    def tag(self, report_path: str | Path, tag: str) -> None:
        entry = self.add_report(report_path)
        clean = tag.strip()
        if clean and clean not in entry.tags:
            entry.tags.append(clean)
            entry.tags.sort()

    def set_note(self, report_path: str | Path, note: str) -> None:
        self.add_report(report_path).note = note

    def set_status(self, report_path: str | Path, status: str) -> None:
        clean = status.strip().lower()
        if clean not in CASE_STATUSES:
            raise ValueError(f"status must be one of {CASE_STATUSES}")
        self.add_report(report_path).status = clean

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": WORKSPACE_SCHEMA_VERSION,
            "name": self.name,
            "version": self.version,
            "entries": [asdict(item) for item in self.entries],
            "notes": list(self.notes),
        }

    def save(self, path: str | Path) -> None:
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(
            json.dumps(self.to_dict(), indent=2), encoding="utf-8"
        )

    @classmethod
    def load(cls, path: str | Path) -> "InvestigationWorkspace":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("workspace root must be a JSON object")
        return cls(
            name=str(data.get("name") or Path(path).stem),
            entries=[
                CaseEntry.from_dict(item)
                for item in data.get("entries") or []
                if isinstance(item, dict)
            ],
            notes=[str(note) for note in data.get("notes") or []],
            version=str(data.get("version") or "1.0"),
        )
