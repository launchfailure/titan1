"""
Plugin system for Titan Decoder Engine.

This package provides the base classes, manifest contract, validation, and
loading mechanisms for extending the engine with custom decoders, analyzers,
detections, and report sections. Third-party plugins should import only from
``titan_decoder.plugins.api`` — the stable, versioned public surface.

Two plugin styles are supported side by side:

- Single-file plugins (API 1.0): a ``.py`` file in a plugin directory.
- Manifest plugins (API 1.1): a directory with ``titan-plugin.json`` plus
  its entry-point module, supporting all four SDK capabilities.

See docs/PLUGIN_API.md for the full contract.
"""

from .contracts import (
    PLUGIN_API_VERSION,
    AnalysisArtifact,
    AnalyzerPlugin,
    DecodeResult,
    DecoderPlugin,
    DetectionFinding,
    DetectionPlugin,
    PluginAnalyzer,
    PluginCapability,
    PluginContext,
    PluginDecoder,
    ReportPlugin,
    ReportSection,
    is_api_compatible,
)
from .manifest import (
    PLUGIN_MANIFEST_FILENAME,
    PLUGIN_MANIFEST_SCHEMA_VERSION,
    PluginManifest,
    validate_manifest,
)
from .registry import (
    RESERVED_RULE_PREFIX,
    LoadedPlugin,
    PluginManager,
    PluginRegistry,
)
from .semver import Version, is_manifest_api_compatible, satisfies
from .validation import (
    PluginValidationReport,
    ValidationIssue,
    validate_plugin,
    validate_plugins,
)

__all__ = [
    "AnalysisArtifact",
    "AnalyzerPlugin",
    "DecodeResult",
    "DecoderPlugin",
    "DetectionFinding",
    "DetectionPlugin",
    "LoadedPlugin",
    "PLUGIN_API_VERSION",
    "PLUGIN_MANIFEST_FILENAME",
    "PLUGIN_MANIFEST_SCHEMA_VERSION",
    "PluginAnalyzer",
    "PluginCapability",
    "PluginContext",
    "PluginDecoder",
    "PluginManager",
    "PluginManifest",
    "PluginRegistry",
    "PluginValidationReport",
    "RESERVED_RULE_PREFIX",
    "ReportPlugin",
    "ReportSection",
    "ValidationIssue",
    "Version",
    "is_api_compatible",
    "is_manifest_api_compatible",
    "satisfies",
    "validate_manifest",
    "validate_plugin",
    "validate_plugins",
]
