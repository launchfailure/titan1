"""Deep plugin validation for authors and operators.

``validate_plugin`` checks a manifest plugin end to end: manifest contents,
API compatibility, entry-point loading, capability match, constructor, and —
via a bounded runtime probe — return types, output limits, artifact naming,
and execution time. The CLI exposes it as ``--plugin-validate``.

The runtime probe executes plugin code in-process on synthetic input. Only
validate plugins you would be willing to run.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import time
from typing import Any

from .contracts import (
    AnalysisArtifact,
    AnalyzerPlugin,
    ConfigExtraction,
    DecodeResult,
    DecoderPlugin,
    DetectionFinding,
    DetectionPlugin,
    ExtractorPlugin,
    PluginContext,
    ReportPlugin,
    ReportSection,
)
from .manifest import PLUGIN_MANIFEST_FILENAME, PluginManifest, validate_manifest
from .registry import RESERVED_RULE_PREFIX, _instantiate_entry_point

_PROBE_INPUT = b"Titan plugin validation probe"


@dataclass(frozen=True)
class ValidationIssue:
    """One problem (or advisory) found while validating a plugin."""

    level: str
    code: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {"level": self.level, "code": self.code, "message": self.message}


@dataclass
class PluginValidationReport:
    """Aggregated validation outcome for one plugin directory."""

    path: str
    ok: bool = True
    manifest: dict[str, Any] | None = None
    issues: list[ValidationIssue] = field(default_factory=list)

    def error(self, code: str, message: str) -> None:
        self.ok = False
        self.issues.append(ValidationIssue("error", code, message))

    def warning(self, code: str, message: str) -> None:
        self.issues.append(ValidationIssue("warning", code, message))

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "ok": self.ok,
            "manifest": self.manifest,
            "issues": [issue.to_dict() for issue in self.issues],
        }


def _probe_decoder(instance: DecoderPlugin, context: PluginContext, report, limit):
    can = instance.can_decode(_PROBE_INPUT, context)
    if not isinstance(can, bool):
        report.error("decoder.can_decode_type", "can_decode must return bool")
    result = instance.decode(_PROBE_INPUT, context)
    if isinstance(result, DecodeResult):
        output = result.data
    elif (
        isinstance(result, tuple)
        and len(result) == 2
        and isinstance(result[0], bytes)
        and isinstance(result[1], bool)
    ):
        output = result[0]
    else:
        report.error(
            "decoder.result_type", "decode must return DecodeResult or (bytes, bool)"
        )
        return
    if len(output) > limit:
        report.error("decoder.output_limit", f"decode output exceeded {limit} bytes")


def _probe_analyzer(instance: AnalyzerPlugin, context: PluginContext, report, limit):
    can = instance.can_analyze(_PROBE_INPUT, context)
    if not isinstance(can, bool):
        report.error("analyzer.can_analyze_type", "can_analyze must return bool")
    artifacts = instance.analyze(_PROBE_INPUT, context)
    if len(artifacts) > context.max_children:
        report.error(
            "analyzer.child_limit",
            f"analyze produced more than {context.max_children} artifacts",
        )
    for item in artifacts:
        if isinstance(item, AnalysisArtifact):
            artifact = item
        elif (
            isinstance(item, tuple)
            and len(item) == 2
            and isinstance(item[0], str)
            and isinstance(item[1], bytes)
        ):
            try:
                artifact = AnalysisArtifact(item[0], item[1])
            except (TypeError, ValueError) as exc:
                report.error("analyzer.artifact_name", str(exc))
                continue
        else:
            report.error(
                "analyzer.result_type",
                "analyze must return AnalysisArtifact or (name, bytes) items",
            )
            continue
        if len(artifact.data) > limit:
            report.error("analyzer.output_limit", f"artifact exceeded {limit} bytes")


def _probe_detection(instance: DetectionPlugin, context: PluginContext, report):
    rule_ids = [str(rule_id) for rule_id in instance.rule_ids]
    if not rule_ids:
        report.error("detection.rule_ids", "detection plugin declares no rule_ids")
    reserved = sorted(
        rule_id
        for rule_id in rule_ids
        if rule_id.upper().startswith(RESERVED_RULE_PREFIX)
    )
    if reserved:
        report.error(
            "detection.reserved_rule_ids",
            f"rule ids use the reserved built-in prefix: {reserved}",
        )
    for finding in instance.detect({}, {}, context):
        if not isinstance(finding, DetectionFinding):
            report.error(
                "detection.result_type", "detect must return DetectionFinding items"
            )
        elif finding.rule_id not in rule_ids:
            report.error(
                "detection.undeclared_rule",
                f"finding uses undeclared rule id: {finding.rule_id}",
            )


def _probe_report(instance: ReportPlugin, context: PluginContext, report):
    for section in instance.build_sections({}, context):
        if not isinstance(section, ReportSection):
            report.error(
                "report.result_type", "build_sections must return ReportSection items"
            )


def _probe_extractor(instance: ExtractorPlugin, context: PluginContext, report):
    can = instance.can_extract(_PROBE_INPUT, context)
    if not isinstance(can, bool):
        report.error("extractor.can_extract_type", "can_extract must return bool")
    values = instance.extract(_PROBE_INPUT, context)
    if len(values) > context.max_children:
        report.error(
            "extractor.child_limit",
            f"extract produced more than {context.max_children} results",
        )
    for value in values:
        if not isinstance(value, ConfigExtraction):
            report.error(
                "extractor.result_type",
                "extract must return ConfigExtraction items",
            )


def validate_plugin(
    path: str | Path,
    *,
    runtime_probe: bool = True,
    max_probe_seconds: float = 1.0,
    max_probe_output_bytes: int = 1024 * 1024,
) -> PluginValidationReport:
    """Validate one manifest plugin directory (or its manifest file path)."""

    plugin_dir = Path(path)
    manifest_path = (
        plugin_dir
        if plugin_dir.name == PLUGIN_MANIFEST_FILENAME
        else plugin_dir / PLUGIN_MANIFEST_FILENAME
    )
    plugin_dir = manifest_path.parent
    report = PluginValidationReport(str(plugin_dir))

    if not manifest_path.exists():
        report.error("manifest.missing", f"missing {PLUGIN_MANIFEST_FILENAME}")
        return report
    try:
        manifest = PluginManifest.load(manifest_path)
        report.manifest = manifest.to_dict()
    except Exception as exc:
        report.error("manifest.invalid", str(exc))
        return report
    for problem in validate_manifest(manifest):
        report.error("manifest.invalid", problem)
    if not report.ok:
        return report

    if "network" in manifest.permissions:
        report.warning(
            "manifest.network_permission",
            "plugin declares the network permission; Titan is offline-first "
            "and permissions are policy metadata, not a sandbox",
        )

    try:
        instance = _instantiate_entry_point(plugin_dir, manifest)
    except Exception as exc:
        report.error("entry_point.load_failed", str(exc))
        return report

    capability_bases = {
        "decoder": DecoderPlugin,
        "analyzer": AnalyzerPlugin,
        "detection": DetectionPlugin,
        "extractor": ExtractorPlugin,
        "report": ReportPlugin,
    }
    implemented = {
        capability
        for capability, base in capability_bases.items()
        if isinstance(instance, base)
    }
    missing = sorted(set(manifest.capabilities) - implemented)
    if missing:
        report.error(
            "entry_point.capability_mismatch",
            f"class does not implement declared capabilities: {missing}",
        )
        return report
    undeclared = sorted(implemented - set(manifest.capabilities))
    if undeclared:
        report.warning(
            "entry_point.undeclared_capability",
            f"class implements capabilities not declared in the manifest: {undeclared}",
        )

    if not runtime_probe:
        return report

    context = PluginContext(
        offline=True,
        max_input_bytes=4096,
        max_output_bytes=max_probe_output_bytes,
        max_children=10,
    )
    start = time.monotonic()
    try:
        if isinstance(instance, DecoderPlugin):
            _probe_decoder(instance, context, report, max_probe_output_bytes)
        if isinstance(instance, AnalyzerPlugin):
            _probe_analyzer(instance, context, report, max_probe_output_bytes)
        if isinstance(instance, DetectionPlugin):
            _probe_detection(instance, context, report)
        if isinstance(instance, ExtractorPlugin):
            _probe_extractor(instance, context, report)
        if isinstance(instance, ReportPlugin):
            _probe_report(instance, context, report)
    except Exception as exc:
        report.error("runtime.exception", f"{type(exc).__name__}: {exc}")
    elapsed = time.monotonic() - start
    if elapsed > max_probe_seconds:
        report.error(
            "runtime.timeout",
            f"runtime probe took {elapsed:.3f}s (limit {max_probe_seconds}s)",
        )
    return report


def validate_plugins(paths) -> tuple[bool, list[dict[str, Any]]]:
    """Validate several plugin paths; returns (all_ok, reports_as_dicts)."""

    results = [validate_plugin(path).to_dict() for path in paths]
    return all(result["ok"] for result in results), results
