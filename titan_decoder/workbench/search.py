"""Cross-report search over every scalar field."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Iterator

from .models import TitanReport

MAX_PREVIEW_CHARS = 140


@dataclass(frozen=True)
class SearchHit:
    """One matching scalar value inside one report."""

    report_path: str
    location: str
    preview: str
    score: int


def _walk(value: Any, path: str = "$") -> "Iterator[tuple[str, Any]]":
    """Yield ``(json_path, scalar)`` for every scalar in *value*, in stable order."""

    if isinstance(value, dict):
        for key in sorted(value, key=str):
            yield from _walk(value[key], f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _walk(item, f"{path}[{index}]")
    else:
        yield path, value


def search_reports(
    reports: Iterable[TitanReport],
    query: str,
    *,
    limit: int = 200,
) -> list[SearchHit]:
    """Case-insensitive substring search across all loaded reports.

    Exact matches rank above prefix matches, which rank above substring
    matches; ties order deterministically by report path and location.
    """

    needle = query.strip().lower()
    if not needle:
        return []
    hits: list[SearchHit] = []
    for report in reports:
        for location, value in _walk(report.data):
            text = str(value)
            lowered = text.lower()
            if needle not in lowered:
                continue
            score = 100 if lowered == needle else 70 if lowered.startswith(needle) else 40
            preview = text.replace("\n", " ")
            if len(preview) > MAX_PREVIEW_CHARS:
                preview = preview[: MAX_PREVIEW_CHARS - 1] + "…"
            hits.append(SearchHit(str(report.path), location, preview, score))
    hits.sort(key=lambda item: (-item.score, item.report_path, item.location))
    return hits[:limit]
