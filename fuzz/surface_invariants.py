"""Cross-surface invariants for Titan's longer adversarial campaigns."""

from __future__ import annotations

import binascii
import json
from pathlib import Path
import time
from typing import Callable

from fuzz.invariants import InvariantError, check_all
from titan_decoder.core.evidence_parsers import parse_evidence_file
from titan_decoder.plugins.manifest import PluginManifest, validate_manifest
from titan_decoder.plugins.worker import _bytes as plugin_bytes
from titan_decoder.plugins.worker import _context as plugin_context
from titan_decoder.server.app import parse_artifact_length
from titan_decoder.workbench.export import (
    export_graph,
    export_iocs_csv,
    export_timeline_csv,
)
from titan_decoder.workbench.models import TitanReport
from titan_decoder.workbench.workspace import InvestigationWorkspace

SURFACES = (
    "decoder-analyzer",
    "evidence-parsers",
    "plugin-transport",
    "server-request",
    "report-load-export",
    "workspace-load-save",
)
EVIDENCE_KINDS = ("dns", "proxy", "firewall", "vpn", "auth", "dhcp")
PER_SURFACE_TIMEOUT = 10.0
OUTPUT_CAP = 512 * 1024


class SurfaceInvariantError(AssertionError):
    """An unexpected exception, timeout, or bound violation on one surface."""

    def __init__(self, surface: str, category: str, detail: str):
        self.surface = surface
        self.category = category
        self.detail = detail
        super().__init__(f"{surface} {category}: {detail}")


def _run_timed(surface: str, operation: Callable[[], None]) -> None:
    start = time.monotonic()
    try:
        operation()
    except SurfaceInvariantError:
        raise
    except Exception as error:
        raise SurfaceInvariantError(
            surface, "unexpected-exception", repr(error)
        ) from error
    elapsed = time.monotonic() - start
    if elapsed > PER_SURFACE_TIMEOUT:
        raise SurfaceInvariantError(
            surface,
            "timeout",
            f"{elapsed:.2f}s exceeded {PER_SURFACE_TIMEOUT:.2f}s",
        )


def _check_decoder_analyzer(data: bytes) -> None:
    try:
        check_all(data)
    except InvariantError as error:
        raise SurfaceInvariantError(
            "decoder-analyzer", "bound-or-contract", str(error)
        ) from error


def _check_evidence(data: bytes, root: Path) -> None:
    paths = (root / "evidence.jsonl", root / "evidence.csv")
    for path in paths:
        path.write_bytes(data)
        for kind in EVIDENCE_KINDS:
            result = parse_evidence_file(path, kind)
            if len(result.events) + len(result.indicators) > len(data) + 1:
                raise SurfaceInvariantError(
                    "evidence-parsers",
                    "output-bound",
                    f"{kind} produced too many records",
                )


def _json_object(data: bytes) -> dict | None:
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def _check_plugin_transport(data: bytes, root: Path) -> None:
    manifest_path = root / "titan-plugin.json"
    manifest_path.write_bytes(data)
    try:
        manifest = PluginManifest.load(manifest_path)
    except (OSError, TypeError, UnicodeError, ValueError):
        manifest = None
    if manifest is not None:
        problems = validate_manifest(manifest)
        if not isinstance(problems, tuple) or len(problems) > 32:
            raise SurfaceInvariantError(
                "plugin-transport", "output-bound", "invalid validation result"
            )

    value = _json_object(data)
    if value is None:
        return
    try:
        context = plugin_context(value.get("context"))
        payload = value.get("payload")
        decoded = plugin_bytes(payload if isinstance(payload, dict) else {})
    except (binascii.Error, OSError, TypeError, UnicodeError, ValueError):
        return
    if len(decoded) > max(OUTPUT_CAP, len(data) * 2):
        raise SurfaceInvariantError(
            "plugin-transport", "output-bound", "decoded request exceeded bound"
        )
    if context.max_input_bytes < 0 or context.max_output_bytes < 0:
        raise SurfaceInvariantError(
            "plugin-transport", "contract", "negative plugin context bound"
        )


def _check_server_request(data: bytes) -> None:
    header = data.decode("ascii", errors="ignore")
    length = parse_artifact_length(header, OUTPUT_CAP)
    if length is not None and not 1 <= length <= OUTPUT_CAP:
        raise SurfaceInvariantError(
            "server-request", "bound", f"accepted invalid length {length}"
        )


def _check_report(data: bytes, root: Path) -> None:
    report_path = root / "report.json"
    report_path.write_bytes(data)
    try:
        report = TitanReport.load(report_path)
    except (OSError, TypeError, UnicodeError, ValueError):
        return

    outputs = (
        root / "iocs.csv",
        root / "timeline.csv",
        root / "graph.json",
        root / "graph.mmd",
    )
    export_iocs_csv([report], outputs[0])
    export_timeline_csv([report], outputs[1])
    export_graph(report, outputs[2], "json")
    export_graph(report, outputs[3], "mermaid")
    for output in outputs:
        if output.stat().st_size > max(OUTPUT_CAP, len(data) * 16):
            raise SurfaceInvariantError(
                "report-load-export",
                "output-bound",
                f"{output.name} exceeded the export bound",
            )


def _check_workspace(data: bytes, root: Path) -> None:
    source = root / "workspace.json"
    destination = root / "workspace-roundtrip.json"
    source.write_bytes(data)
    try:
        workspace = InvestigationWorkspace.load(source)
    except (OSError, TypeError, UnicodeError, ValueError):
        return
    workspace.save(destination)
    if destination.stat().st_size > max(OUTPUT_CAP, len(data) * 16):
        raise SurfaceInvariantError(
            "workspace-load-save", "output-bound", "round trip exceeded bound"
        )


def check_surfaces(data: bytes, root: Path) -> None:
    """Run hostile bytes through six bounded public-facing surfaces."""

    root.mkdir(parents=True, exist_ok=True)
    _run_timed("decoder-analyzer", lambda: _check_decoder_analyzer(data))
    _run_timed("evidence-parsers", lambda: _check_evidence(data, root))
    _run_timed("plugin-transport", lambda: _check_plugin_transport(data, root))
    _run_timed("server-request", lambda: _check_server_request(data))
    _run_timed("report-load-export", lambda: _check_report(data, root))
    _run_timed("workspace-load-save", lambda: _check_workspace(data, root))
