"""Plugin discovery, loading, and registration.

``PluginManager`` supports both plugin styles side by side:

- **Single-file plugins** (API 1.0): a bare ``.py`` file dropped in a plugin
  directory, discovered exactly as before the SDK existed.
- **Manifest plugins** (API 1.1): a subdirectory containing
  ``titan-plugin.json`` plus its entry-point module, validated against the
  manifest contract, loaded in dependency order.

Failures never abort discovery: a broken plugin is skipped with a logged
warning and recorded in ``self.errors`` so ``--plugin-list`` can surface it.
"""

from __future__ import annotations

from dataclasses import dataclass
import importlib.util
import logging
from pathlib import Path
import sys
from typing import Any

from .contracts import (
    PLUGIN_API_VERSION,
    AnalyzerPlugin,
    DecoderPlugin,
    DetectionPlugin,
    ExtractorPlugin,
    PluginAnalyzer,
    PluginDecoder,
    ReportPlugin,
    is_api_compatible,
)
from .manifest import PLUGIN_MANIFEST_FILENAME, PluginManifest, validate_manifest
from .semver import satisfies

logger = logging.getLogger(__name__)

# Rule-ID prefix reserved for built-in detection rules. Plugins may not emit
# rules under it, so a plugin can never impersonate a built-in detection —
# the same guarantee rule packs enforce.
RESERVED_RULE_PREFIX = "TITAN-"


@dataclass(frozen=True)
class LoadedPlugin:
    """One successfully loaded manifest plugin."""

    manifest: PluginManifest
    instance: Any
    path: Path


class PluginManager:
    """Manages loading and registration of plugins."""

    def __init__(
        self,
        plugin_dirs: list[Path] | None = None,
        *,
        execution_mode: str = "isolated",
        offline: bool = True,
        timeout_seconds: int = 10,
        max_input_bytes: int = 100 * 1024 * 1024,
        max_output_bytes: int = 16 * 1024 * 1024,
        max_memory_mb: int = 512,
        max_children: int = 100,
    ):
        self.plugin_dirs = plugin_dirs or []
        if execution_mode not in {"isolated", "in_process"}:
            raise ValueError("plugin execution_mode must be isolated or in_process")
        self.execution_mode = execution_mode
        self.offline = bool(offline)
        self.isolation_limits = {
            "offline": self.offline,
            "timeout_seconds": timeout_seconds,
            "max_input_bytes": max_input_bytes,
            "max_output_bytes": max_output_bytes,
            "max_memory_mb": max_memory_mb,
            "max_children": max_children,
        }
        self.decoders: list[PluginDecoder] = []
        self.analyzers: list[PluginAnalyzer] = []
        self.detections: list[DetectionPlugin] = []
        self.extractors: list[ExtractorPlugin] = []
        self.reports: list[ReportPlugin] = []
        self.loaded_plugins: dict[str, Any] = {}
        self.manifest_plugins: dict[str, LoadedPlugin] = {}
        self.errors: list[dict[str, str]] = []

    def add_plugin_dir(self, plugin_dir: Path):
        """Add a directory to search for plugins."""
        plugin_dir = Path(plugin_dir)
        if plugin_dir not in self.plugin_dirs:
            self.plugin_dirs.append(plugin_dir)

    def load_plugins(self):
        """Load all plugins from configured directories."""
        for plugin_dir in self.plugin_dirs:
            if plugin_dir.exists() and plugin_dir.is_dir():
                self._load_plugins_from_dir(plugin_dir)
        self._load_manifest_plugins()

        # Sort by priority (highest first); name breaks ties so ordering is
        # deterministic across runs and platforms.
        def _key(plugin):
            return (-int(getattr(plugin, "priority", 0)), str(plugin.name))

        self.decoders.sort(key=_key)
        self.analyzers.sort(key=_key)
        self.detections.sort(key=_key)
        self.extractors.sort(key=_key)
        self.reports.sort(key=_key)

    # Package-infrastructure modules in the built-in plugin dir that are not
    # plugins and must not be discovered/loaded as such.
    _RESERVED_MODULES = frozenset(
        {
            "api.py",
            "contracts.py",
            "manifest.py",
            "registry.py",
            "semver.py",
            "validation.py",
            "isolation.py",
            "worker.py",
        }
    )

    def _load_plugins_from_dir(self, plugin_dir: Path):
        """Load single-file plugins from a specific directory."""
        for item in plugin_dir.iterdir():
            if (
                item.is_file()
                and item.suffix == ".py"
                and not item.name.startswith("_")
                and item.name not in self._RESERVED_MODULES
            ):
                self._load_plugin_file(item)

    def _load_plugin_file(self, plugin_file: Path):
        """Load a single-file plugin."""
        try:
            # Create module name
            module_name = f"titan_decoder_plugins_{plugin_file.stem}"

            # Load the module
            spec = importlib.util.spec_from_file_location(module_name, plugin_file)
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                sys.modules[module_name] = module
                spec.loader.exec_module(module)

                # Enforce the versioned API contract: a plugin may declare the
                # API version it targets; skip it on a breaking (MAJOR) mismatch
                # rather than loading an incompatible extension.
                declared = getattr(module, "PLUGIN_API_VERSION", None)
                if declared is not None and not is_api_compatible(str(declared)):
                    logger.warning(
                        "Skipping plugin %s: declares API %s, engine provides %s "
                        "(incompatible major version)",
                        plugin_file.name,
                        declared,
                        PLUGIN_API_VERSION,
                    )
                    return

                # Find plugin classes in the module
                self._register_plugin_classes(module, plugin_file.stem)

                self.loaded_plugins[plugin_file.stem] = module

        except Exception as e:
            logger.warning("Failed to load plugin %s: %s", plugin_file, e)
            self.errors.append({"path": str(plugin_file), "error": str(e)})

    def _register_plugin_classes(self, module, plugin_name: str):
        """Register plugin classes from a loaded single-file module."""
        abstract = {
            PluginDecoder,
            PluginAnalyzer,
            DecoderPlugin,
            AnalyzerPlugin,
            DetectionPlugin,
            ExtractorPlugin,
            ReportPlugin,
        }
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if not isinstance(attr, type) or attr in abstract:
                continue
            try:
                if issubclass(attr, PluginDecoder):
                    self.decoders.append(attr())
                    logger.info("Loaded decoder plugin: %s", self.decoders[-1].name)
                elif issubclass(attr, PluginAnalyzer):
                    self.analyzers.append(attr())
                    logger.info("Loaded analyzer plugin: %s", self.analyzers[-1].name)
                elif issubclass(attr, DetectionPlugin):
                    instance = attr()
                    self._check_rule_ids(instance)
                    self.detections.append(instance)
                    logger.info("Loaded detection plugin: %s", instance.name)
                elif issubclass(attr, ExtractorPlugin):
                    self.extractors.append(attr())
                    logger.info("Loaded extractor plugin: %s", self.extractors[-1].name)
                elif issubclass(attr, ReportPlugin):
                    self.reports.append(attr())
                    logger.info("Loaded report plugin: %s", self.reports[-1].name)
            except Exception as e:
                logger.warning(
                    "Failed to instantiate %s from plugin %s: %s",
                    attr_name,
                    plugin_name,
                    e,
                )

    # --- Manifest plugins -------------------------------------------------

    def _manifest_candidates(self) -> list[Path]:
        candidates: set[Path] = set()
        for directory in self.plugin_dirs:
            directory = Path(directory)
            if not directory.is_dir():
                continue
            if (directory / PLUGIN_MANIFEST_FILENAME).exists():
                candidates.add(directory)
            for child in directory.iterdir():
                if child.is_dir() and (child / PLUGIN_MANIFEST_FILENAME).exists():
                    candidates.add(child)
        return sorted(candidates, key=str)

    def _load_manifest_plugins(self) -> None:
        """Discover and load manifest plugins in dependency order."""
        manifests: dict[Path, PluginManifest] = {}
        for path in self._manifest_candidates():
            try:
                manifests[path] = PluginManifest.load(path / PLUGIN_MANIFEST_FILENAME)
            except Exception as exc:
                logger.warning("Failed to read plugin manifest %s: %s", path, exc)
                self.errors.append({"path": str(path), "error": str(exc)})

        # Order by dependency edges (Kahn), name-sorted for determinism, so a
        # plugin can depend on another regardless of directory order. Cyclic
        # or unresolvable remainders load last and fail their dependency check
        # with a precise error.
        by_id = {manifest.plugin_id: path for path, manifest in manifests.items()}
        ordered: list[Path] = []
        remaining = dict(manifests)
        while remaining:
            ready = [
                path
                for path, manifest in remaining.items()
                if all(
                    dependency not in by_id or by_id[dependency] not in remaining
                    for dependency in manifest.dependencies
                )
            ]
            if not ready:
                ready = list(remaining)  # cycle: load in stable order, fail below
            for path in sorted(ready, key=str):
                ordered.append(path)
                remaining.pop(path)

        for path in ordered:
            self._load_manifest_plugin(path, manifests[path])

    def _load_manifest_plugin(self, path: Path, manifest: PluginManifest) -> None:
        try:
            problems = validate_manifest(manifest)
            if problems:
                raise ValueError("; ".join(problems))
            if manifest.plugin_id in self.manifest_plugins:
                raise ValueError(f"duplicate plugin id: {manifest.plugin_id}")

            for dependency, requirement in sorted(manifest.dependencies.items()):
                loaded = self.manifest_plugins.get(dependency)
                if loaded is None:
                    raise ValueError(f"missing dependency: {dependency}")
                if not satisfies(loaded.manifest.version, requirement):
                    raise ValueError(
                        f"dependency {dependency} version "
                        f"{loaded.manifest.version} does not satisfy {requirement!r}"
                    )

            if self.execution_mode == "isolated":
                from .isolation import build_isolated_proxies

                instances, _metadata = build_isolated_proxies(
                    path, manifest, **self.isolation_limits
                )
            else:
                instances = [_instantiate_entry_point(path, manifest)]

            registered = False
            for instance in instances:
                if isinstance(instance, PluginDecoder):
                    self.decoders.append(instance)
                    registered = True
                if isinstance(instance, PluginAnalyzer):
                    self.analyzers.append(instance)
                    registered = True
                if isinstance(instance, DetectionPlugin):
                    self._check_rule_ids(instance)
                    self.detections.append(instance)
                    registered = True
                if isinstance(instance, ExtractorPlugin):
                    self.extractors.append(instance)
                    registered = True
                if isinstance(instance, ReportPlugin):
                    self.reports.append(instance)
                    registered = True
            if not registered:
                raise TypeError(
                    "entry point class implements no supported plugin base class"
                )

            self.manifest_plugins[manifest.plugin_id] = LoadedPlugin(
                manifest, instances[0], path
            )
            logger.info(
                "Loaded manifest plugin: %s %s", manifest.plugin_id, manifest.version
            )
        except Exception as exc:
            logger.warning("Failed to load plugin %s: %s", path, exc)
            self.errors.append({"path": str(path), "error": str(exc)})

    def _check_rule_ids(self, instance: DetectionPlugin) -> None:
        """Enforce rule-ID reservations and uniqueness for detection plugins."""
        rule_ids = [str(rule_id) for rule_id in instance.rule_ids]
        if not rule_ids:
            raise ValueError("detection plugin declares no rule_ids")
        reserved = sorted(
            rule_id
            for rule_id in rule_ids
            if rule_id.upper().startswith(RESERVED_RULE_PREFIX)
        )
        if reserved:
            raise ValueError(
                f"rule ids use the reserved built-in prefix "
                f"{RESERVED_RULE_PREFIX!r}: {reserved}"
            )
        used = {rid for plugin in self.detections for rid in plugin.rule_ids}
        duplicates = sorted(used & set(rule_ids))
        if duplicates:
            raise ValueError(f"duplicate detection rule ids: {duplicates}")

    # --- Accessors ----------------------------------------------------------

    def get_decoders(self) -> list[PluginDecoder]:
        """Get all loaded decoder plugins."""
        return self.decoders.copy()

    def get_analyzers(self) -> list[PluginAnalyzer]:
        """Get all loaded analyzer plugins."""
        return self.analyzers.copy()

    def get_detections(self) -> list[DetectionPlugin]:
        """Get all loaded detection plugins."""
        return self.detections.copy()

    def get_extractors(self) -> list[ExtractorPlugin]:
        """Get all loaded malware configuration extractor plugins."""
        return self.extractors.copy()

    def get_reports(self) -> list[ReportPlugin]:
        """Get all loaded report plugins."""
        return self.reports.copy()

    def get_plugin_info(self) -> dict[str, Any]:
        """Get information about loaded plugins."""
        return {
            "api_version": PLUGIN_API_VERSION,
            "execution_mode": self.execution_mode,
            "legacy_plugins_in_process": bool(self.loaded_plugins),
            "plugin_dirs": [str(d) for d in self.plugin_dirs],
            "loaded_plugins": list(self.loaded_plugins.keys()),
            "manifest_plugins": [
                loaded.manifest.to_dict()
                for _, loaded in sorted(self.manifest_plugins.items())
            ],
            "decoders": [d.name for d in self.decoders],
            "analyzers": [a.name for a in self.analyzers],
            "detections": [d.name for d in self.detections],
            "extractors": [e.name for e in self.extractors],
            "reports": [r.name for r in self.reports],
            "errors": list(self.errors),
        }


def _instantiate_entry_point(plugin_dir: Path, manifest: PluginManifest) -> Any:
    """Import a manifest plugin's entry-point module and instantiate its class."""

    module_name, class_name = manifest.entry_point.split(":", 1)
    module_path = plugin_dir / (module_name.replace(".", "/") + ".py")
    package_path = plugin_dir / module_name.replace(".", "/") / "__init__.py"
    source = module_path if module_path.exists() else package_path
    if not source.exists():
        raise FileNotFoundError(f"entry point module not found: {module_name}")

    unique = "titan_plugin_" + manifest.plugin_id.replace(".", "_").replace("-", "_")
    spec = importlib.util.spec_from_file_location(unique, source)
    if spec is None or spec.loader is None:
        raise ImportError(f"unable to create module spec for {source}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[unique] = module
    spec.loader.exec_module(module)

    target = getattr(module, class_name, None)
    if target is None:
        raise AttributeError(f"entry point class not found: {class_name}")
    if not isinstance(target, type):
        raise TypeError(f"entry point {class_name} is not a class")
    return target()


# Compatibility alias for callers using the SDK package's name.
PluginRegistry = PluginManager
