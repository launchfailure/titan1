"""Plugin SDK v1 contracts: base classes and typed results.

This module defines the four plugin SDKs (decoder, analyzer, detection,
report) plus the typed values they exchange with the engine. Everything here
is part of the versioned public API surface re-exported by
``titan_decoder.plugins.api`` — third-party plugins import only from there.

Compatibility: the original single-file plugin contract (``PluginDecoder`` /
``PluginAnalyzer`` with ``(bytes, bool)`` and ``(name, bytes)`` results) is
unchanged and remains fully supported. The SDK classes subclass those bases
and add an optional :class:`PluginContext` argument and typed results;
:class:`DecodeResult` and :class:`AnalysisArtifact` unpack like the legacy
tuples, so the engine consumes both styles identically.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Iterator, Mapping, Sequence

# Versioned plugin API contract (MAJOR.MINOR). A third party ships a plugin
# against this interface without reading engine internals.
#
# MAJOR bump = breaking change to base-class method signatures / semantics.
# MINOR bump = additive, backward-compatible extension.
#
# History: 1.0 = single-file PluginDecoder/PluginAnalyzer contract.
#          1.1 = adds the manifest-based SDK (detection/report plugins,
#                PluginContext, typed results) — purely additive.
PLUGIN_API_VERSION = "1.1"


def _api_major(version: str) -> int:
    try:
        return int(str(version).split(".", 1)[0])
    except (ValueError, AttributeError):
        return -1


def is_api_compatible(declared: str) -> bool:
    """Return True if a plugin declaring ``declared`` is loadable here.

    Compatible when the MAJOR versions match: the engine may add MINOR
    features without breaking older plugins, but a MAJOR change is breaking.
    Malformed declarations are incompatible rather than an error.
    """
    return _api_major(declared) == _api_major(PLUGIN_API_VERSION)


class PluginCapability(str, Enum):
    """Capabilities a plugin may declare in its manifest."""

    DECODER = "decoder"
    ANALYZER = "analyzer"
    DETECTION = "detection"
    REPORT = "report"


@dataclass(frozen=True)
class PluginContext:
    """Execution context handed to SDK plugins.

    Communicates the engine's offline stance and resource bounds. Plugins
    must honor these limits; validation probes them and the engine treats
    violations as plugin failures.
    """

    config: Mapping[str, Any] = field(default_factory=dict)
    offline: bool = True
    max_input_bytes: int = 100 * 1024 * 1024
    max_output_bytes: int = 100 * 1024 * 1024
    max_children: int = 100
    working_directory: Path | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "config", dict(self.config))


@dataclass(frozen=True)
class DecodeResult:
    """Typed decoder result. Unpacks like the legacy ``(bytes, bool)``."""

    data: bytes
    success: bool
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.data, bytes):
            raise TypeError("DecodeResult.data must be bytes")
        object.__setattr__(self, "metadata", dict(self.metadata))

    def __iter__(self) -> Iterator[Any]:
        # Tuple-compatibility: `decoded, success = plugin.decode(data)` works
        # whether the plugin returns a DecodeResult or a legacy tuple.
        yield self.data
        yield self.success


@dataclass(frozen=True)
class AnalysisArtifact:
    """Typed analyzer artifact. Unpacks like the legacy ``(name, bytes)``."""

    name: str
    data: bytes
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.name or Path(self.name).name != self.name:
            raise ValueError("artifact name must be a non-empty basename")
        if not isinstance(self.data, bytes):
            raise TypeError("AnalysisArtifact.data must be bytes")
        object.__setattr__(self, "metadata", dict(self.metadata))

    def __iter__(self) -> Iterator[Any]:
        yield self.name
        yield self.data


@dataclass(frozen=True)
class DetectionFinding:
    """One detection produced by a detection plugin.

    Mirrors the built-in detection dictionary shape so plugin findings merge
    into ``report["detections"]`` and feed risk scoring like rule results.
    """

    rule_id: str
    name: str
    description: str
    severity: str
    attack_ids: tuple[str, ...] = ()
    evidence: tuple[Mapping[str, Any], ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.rule_id or not self.name:
            raise ValueError("rule_id and name are required")
        if self.severity not in {"low", "medium", "high", "critical"}:
            raise ValueError("severity must be low, medium, high, or critical")
        object.__setattr__(self, "attack_ids", tuple(sorted(set(self.attack_ids))))
        object.__setattr__(
            self, "evidence", tuple(dict(item) for item in self.evidence)
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "description": self.description,
            "severity": self.severity,
            "attack_ids": list(self.attack_ids),
            "evidence": [dict(item) for item in self.evidence],
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class ReportSection:
    """One analyst-facing section contributed by a report plugin."""

    section_id: str
    title: str
    content: Any
    order: int = 100
    formats: tuple[str, ...] = ("json",)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.section_id or not self.title:
            raise ValueError("section_id and title are required")
        if not set(self.formats) <= {"json", "markdown", "html"}:
            raise ValueError("formats must be a subset of json/markdown/html")
        object.__setattr__(self, "formats", tuple(sorted(set(self.formats))))
        object.__setattr__(self, "metadata", dict(self.metadata))

    def to_dict(self) -> dict[str, Any]:
        return {
            "section_id": self.section_id,
            "title": self.title,
            "content": self.content,
            "order": self.order,
            "formats": list(self.formats),
            "metadata": dict(self.metadata),
        }


class PluginDecoder(ABC):
    """Base class for plugin decoders (single-file plugin contract, API 1.0).

    Contract (enforced by the fuzz invariants): ``can_decode`` and ``decode``
    must never raise, must return the declared types, must bound their
    output, and must terminate quickly on any input, including hostile bytes.
    """

    @abstractmethod
    def can_decode(self, data: bytes) -> bool:
        """Check if this decoder can handle the data."""

    @abstractmethod
    def decode(self, data: bytes) -> "DecodeResult | tuple[bytes, bool]":
        """Decode the data. Return (decoded_data, success).

        A typed :class:`DecodeResult` is also accepted — it unpacks
        identically, so the engine consumes both forms the same way.
        """

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the decoder."""

    @property
    def priority(self) -> int:
        """Priority for decoder ordering (higher = tried first). Default 0."""
        return 0


class PluginAnalyzer(ABC):
    """Base class for plugin analyzers (single-file plugin contract, API 1.0)."""

    @abstractmethod
    def can_analyze(self, data: bytes) -> bool:
        """Check if this analyzer can handle the data."""

    @abstractmethod
    def analyze(
        self, data: bytes
    ) -> "Sequence[AnalysisArtifact] | Sequence[tuple[str, bytes]]":
        """Analyze the data and return list of (name, content) tuples.

        Typed :class:`AnalysisArtifact` items are also accepted — they
        unpack identically to the tuples.
        """

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the analyzer."""

    @property
    def priority(self) -> int:
        """Priority for analyzer ordering (higher = tried first). Default 0."""
        return 0


class DecoderPlugin(PluginDecoder):
    """Decoder SDK base class (manifest plugins, API 1.1).

    Same engine-facing contract as :class:`PluginDecoder`, with an optional
    context argument and an optional typed result. Because
    :class:`DecodeResult` unpacks like ``(bytes, bool)``, either return type
    is valid.
    """

    api_version = PLUGIN_API_VERSION

    @abstractmethod
    def can_decode(self, data: bytes, context: PluginContext | None = None) -> bool: ...

    @abstractmethod
    def decode(
        self, data: bytes, context: PluginContext | None = None
    ) -> DecodeResult | tuple[bytes, bool]: ...


class AnalyzerPlugin(PluginAnalyzer):
    """Analyzer SDK base class (manifest plugins, API 1.1)."""

    api_version = PLUGIN_API_VERSION

    @abstractmethod
    def can_analyze(
        self, data: bytes, context: PluginContext | None = None
    ) -> bool: ...

    @abstractmethod
    def analyze(
        self, data: bytes, context: PluginContext | None = None
    ) -> Sequence[AnalysisArtifact] | Sequence[tuple[str, bytes]]: ...


class DetectionPlugin(ABC):
    """Detection SDK base class (manifest plugins, API 1.1).

    ``rule_ids`` must declare every rule the plugin can emit. IDs are
    validated at load time: the ``TITAN-`` prefix is reserved for built-in
    rules, and IDs must not collide with other loaded plugins.
    """

    api_version = PLUGIN_API_VERSION
    priority = 0

    @property
    @abstractmethod
    def name(self) -> str: ...

    @property
    @abstractmethod
    def rule_ids(self) -> Sequence[str]: ...

    @abstractmethod
    def detect(
        self,
        report: Mapping[str, Any],
        iocs: Mapping[str, Any],
        context: PluginContext | None = None,
    ) -> Sequence[DetectionFinding]: ...


class ReportPlugin(ABC):
    """Report SDK base class (manifest plugins, API 1.1)."""

    api_version = PLUGIN_API_VERSION
    priority = 0

    @property
    @abstractmethod
    def name(self) -> str: ...

    @abstractmethod
    def build_sections(
        self,
        report: Mapping[str, Any],
        context: PluginContext | None = None,
    ) -> Sequence[ReportSection]: ...
