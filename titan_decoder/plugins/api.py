"""Stable, versioned public plugin API for Titan.

Third-party plugins should import **only** from this module. It is the
compatibility surface: everything here is covered by the
``PLUGIN_API_VERSION`` contract (see docs/PLUGIN_API.md), so a plugin written
against it keeps working across engine releases with the same MAJOR version,
without depending on engine internals.

Single-file plugin (``myplugin.py`` dropped in a plugin dir, API 1.0)::

    from titan_decoder.plugins.api import PluginDecoder, PLUGIN_API_VERSION

    PLUGIN_API_VERSION = PLUGIN_API_VERSION  # declare the API you built against

    class Rot47Decoder(PluginDecoder):
        @property
        def name(self):
            return "ROT47"

        def can_decode(self, data):
            return data[:1].isascii()

        def decode(self, data):
            out = bytes((b - 33 + 47) % 94 + 33 if 33 <= b <= 126 else b
                        for b in data)
            return out, out != data

Manifest plugin (a directory with ``titan-plugin.json``, API 1.1+) may use any
of the five SDK base classes — :class:`DecoderPlugin`,
:class:`AnalyzerPlugin`, :class:`DetectionPlugin`, :class:`ExtractorPlugin`,
:class:`ReportPlugin` —
with typed results and an optional :class:`PluginContext`. See
``examples/plugins/`` for one complete plugin per capability.

Contract every plugin must uphold (enforced by the fuzz invariants and
``--plugin-validate``): ``can_decode``/``can_analyze`` and
``decode``/``analyze``/``detect``/``build_sections`` must never raise, must
return the declared types, must bound their output, and must terminate
quickly on any input, including hostile bytes.
"""

from __future__ import annotations

from .contracts import (
    PLUGIN_API_VERSION,
    AnalysisArtifact,
    AnalyzerPlugin,
    ConfigExtraction,
    DecodeResult,
    DecoderPlugin,
    DetectionFinding,
    DetectionPlugin,
    ExtractorPlugin,
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
from .semver import Version, is_manifest_api_compatible, satisfies
from .validation import (
    PluginValidationReport,
    ValidationIssue,
    validate_plugin,
    validate_plugins,
)

__all__ = [
    "PLUGIN_API_VERSION",
    "PLUGIN_MANIFEST_FILENAME",
    "PLUGIN_MANIFEST_SCHEMA_VERSION",
    "AnalysisArtifact",
    "AnalyzerPlugin",
    "ConfigExtraction",
    "DecodeResult",
    "DecoderPlugin",
    "DetectionFinding",
    "DetectionPlugin",
    "ExtractorPlugin",
    "PluginAnalyzer",
    "PluginCapability",
    "PluginContext",
    "PluginDecoder",
    "PluginManifest",
    "PluginValidationReport",
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
