"""Helpers for locating and validating the Phase 5.1 schema."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

SCHEMA_FILENAME = "correlation-report-v1.0.schema.json"


def schema_path() -> Path:
    return Path(__file__).resolve().parents[2] / "schemas" / SCHEMA_FILENAME


def load_schema() -> dict[str, Any]:
    return json.loads(schema_path().read_text(encoding="utf-8"))


def validate_report_shape(report: Mapping[str, Any]) -> list[str]:
    """Dependency-free structural validation used by the core package."""

    errors: list[str] = []
    required = {"schema_version", "subject_analysis_id", "relationships"}
    missing = sorted(required - set(report))
    if missing:
        errors.append(f"missing required fields: {missing}")
    if report.get("schema_version") != "1.0":
        errors.append("schema_version must be '1.0'")
    if "relationships" in report and not isinstance(report["relationships"], list):
        errors.append("relationships must be a list")
    return errors
