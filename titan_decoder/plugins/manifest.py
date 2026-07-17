"""Plugin manifest loading and validation.

A manifest plugin is a directory containing ``titan-plugin.json`` plus its
entry-point module. The manifest declares identity, versions, capabilities,
permissions, and dependencies; the JSON Schema contract lives in
``schemas/titan-plugin-manifest-v1.0.schema.json``.

Permission declarations are policy metadata for operators and reviewers, not
a sandbox: plugins execute in-process (see docs/PLUGIN_API.md).
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path
import re
from typing import Any, Mapping

from .contracts import PLUGIN_API_VERSION, PluginCapability
from .semver import Version, is_manifest_api_compatible

PLUGIN_MANIFEST_FILENAME = "titan-plugin.json"
PLUGIN_MANIFEST_SCHEMA_VERSION = "1.0"

MAX_MANIFEST_BYTES = 64 * 1024

SUPPORTED_PERMISSIONS = frozenset(
    {"filesystem.read", "filesystem.write", "network", "configuration"}
)

_PLUGIN_ID_RE = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
_ENTRY_POINT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*:[A-Za-z_][A-Za-z0-9_]*$")


@dataclass(frozen=True)
class PluginManifest:
    """Parsed ``titan-plugin.json`` contents."""

    plugin_id: str
    name: str
    version: str
    api_version: str
    entry_point: str
    capabilities: tuple[str, ...]
    description: str = ""
    author: str = ""
    license: str = ""
    homepage: str = ""
    permissions: tuple[str, ...] = ()
    dependencies: Mapping[str, str] = field(default_factory=dict)
    schema_version: str = PLUGIN_MANIFEST_SCHEMA_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(self, "capabilities", tuple(sorted(set(self.capabilities))))
        object.__setattr__(self, "permissions", tuple(sorted(set(self.permissions))))
        object.__setattr__(self, "dependencies", dict(self.dependencies))

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "PluginManifest":
        return cls(
            plugin_id=str(data.get("id", "")),
            name=str(data.get("name", "")),
            version=str(data.get("version", "")),
            api_version=str(data.get("api_version", "")),
            entry_point=str(data.get("entry_point", "")),
            capabilities=tuple(data.get("capabilities") or ()),
            description=str(data.get("description", "")),
            author=str(data.get("author", "")),
            license=str(data.get("license", "")),
            homepage=str(data.get("homepage", "")),
            permissions=tuple(data.get("permissions") or ()),
            dependencies=dict(data.get("dependencies") or {}),
            schema_version=str(
                data.get("schema_version") or PLUGIN_MANIFEST_SCHEMA_VERSION
            ),
        )

    @classmethod
    def load(cls, path: str | Path) -> "PluginManifest":
        manifest_path = Path(path)
        if manifest_path.stat().st_size > MAX_MANIFEST_BYTES:
            raise ValueError(f"manifest exceeds {MAX_MANIFEST_BYTES} bytes")
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("manifest root must be a JSON object")
        return cls.from_dict(data)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "id": self.plugin_id,
            "name": self.name,
            "version": self.version,
            "api_version": self.api_version,
            "entry_point": self.entry_point,
            "capabilities": list(self.capabilities),
            "description": self.description,
            "author": self.author,
            "license": self.license,
            "homepage": self.homepage,
            "permissions": list(self.permissions),
            "dependencies": dict(self.dependencies),
        }


def validate_manifest(
    manifest: PluginManifest,
    provided_api_version: str = PLUGIN_API_VERSION,
) -> tuple[str, ...]:
    """Return every validation problem for *manifest* (empty when valid)."""

    errors: list[str] = []
    if manifest.schema_version != PLUGIN_MANIFEST_SCHEMA_VERSION:
        errors.append(
            f"unsupported schema_version: {manifest.schema_version!r} "
            f"(expected {PLUGIN_MANIFEST_SCHEMA_VERSION!r})"
        )
    if not _PLUGIN_ID_RE.fullmatch(manifest.plugin_id):
        errors.append(
            "invalid plugin id (lowercase alphanumeric segments separated "
            "by '.', '_', or '-')"
        )
    if not manifest.name.strip():
        errors.append("name must not be empty")

    for label, value in (
        ("version", manifest.version),
        ("api_version", manifest.api_version),
    ):
        try:
            Version.parse(value)
        except ValueError:
            errors.append(f"invalid {label}: {value!r}")

    if not _ENTRY_POINT_RE.fullmatch(manifest.entry_point):
        errors.append("entry_point must have the form module:ClassName")

    supported = {capability.value for capability in PluginCapability}
    if not manifest.capabilities:
        errors.append("capabilities must not be empty")
    unknown = sorted(set(manifest.capabilities) - supported)
    if unknown:
        errors.append(f"unsupported capabilities: {unknown}")

    bad_permissions = sorted(set(manifest.permissions) - SUPPORTED_PERMISSIONS)
    if bad_permissions:
        errors.append(f"unsupported permissions: {bad_permissions}")

    for dependency, requirement in sorted(manifest.dependencies.items()):
        if not _PLUGIN_ID_RE.fullmatch(dependency):
            errors.append(f"invalid dependency id: {dependency!r}")
        try:
            from .semver import satisfies

            satisfies("0.0.0", requirement)
        except ValueError:
            errors.append(
                f"invalid dependency requirement for {dependency}: {requirement!r}"
            )

    try:
        if not is_manifest_api_compatible(manifest.api_version, provided_api_version):
            errors.append(
                f"incompatible API version: plugin declares "
                f"{manifest.api_version}, engine provides {provided_api_version}"
            )
    except ValueError:
        pass  # already reported as invalid api_version

    return tuple(errors)
