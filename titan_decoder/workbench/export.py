"""Workbench exports: CSVs, graph formats, and portable case bundles."""

from __future__ import annotations

import csv
from dataclasses import asdict
import json
from pathlib import Path
from typing import Iterable
import zipfile

from .models import TitanReport
from .workspace import InvestigationWorkspace

BUNDLE_SCHEMA_VERSION = "analyst-bundle-v1.0"

GRAPH_FORMATS = ("json", "dot", "mermaid")


def export_iocs_csv(reports: Iterable[TitanReport], path: str | Path) -> None:
    """Write every indicator from every report as one CSV."""

    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["report_path", "analysis_id", "indicator_type", "value"])
        for report in reports:
            for kind, value in report.indicators():
                writer.writerow(
                    [str(report.path), report.summary.analysis_id, kind, value]
                )


def export_timeline_csv(reports: Iterable[TitanReport], path: str | Path) -> None:
    """Write every timeline event from every report as one CSV."""

    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["report_path", "analysis_id", "timestamp", "kind", "summary"])
        for report in reports:
            for event in report.timeline():
                writer.writerow(
                    [
                        str(report.path),
                        report.summary.analysis_id,
                        event.get("timestamp") or event.get("time") or "",
                        event.get("kind")
                        or event.get("event_type")
                        or event.get("type")
                        or "",
                        event.get("summary")
                        or event.get("message")
                        or event.get("description")
                        or "",
                    ]
                )


def export_graph(report: TitanReport, path: str | Path, fmt: str = "mermaid") -> None:
    """Export the active report's analysis graph via the core exporter."""

    if fmt not in GRAPH_FORMATS:
        raise ValueError(f"graph format must be one of {GRAPH_FORMATS}")
    from ..core.graph_export import GraphExporter

    exporter = GraphExporter(
        report.nodes(),
        intelligence=report.data.get("intelligence") or {},
        threat_intelligence=report.data.get("threat_intelligence") or {},
    )
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if fmt == "json":
        exporter.save_json(destination)
    elif fmt == "dot":
        exporter.save_dot(destination)
    else:
        exporter.save_mermaid(destination)


def export_case_bundle(
    workspace: InvestigationWorkspace,
    reports: Iterable[TitanReport],
    path: str | Path,
) -> None:
    """Write a portable ZIP: workspace, manifest, and full report copies."""

    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    reports = list(reports)
    with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("workspace.json", json.dumps(workspace.to_dict(), indent=2))
        manifest = {
            "schema_version": BUNDLE_SCHEMA_VERSION,
            "workspace": workspace.name,
            "report_count": len(reports),
            "reports": [asdict(report.summary) for report in reports],
        }
        archive.writestr("manifest.json", json.dumps(manifest, indent=2))
        for index, report in enumerate(reports, 1):
            archive.writestr(
                f"reports/{index:03d}-{report.path.name}",
                json.dumps(report.data, indent=2),
            )
