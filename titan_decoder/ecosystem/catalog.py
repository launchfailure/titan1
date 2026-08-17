"""Offline community plugin-catalog validation and compatibility filtering."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from titan_decoder.plugins.semver import Version

_ID = re.compile(r"^[a-z0-9]+(?:[._-][a-z0-9]+)+$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_CAPABILITIES = {"decoder", "analyzer", "detection", "extractor", "report"}


def validate_catalog(value: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(value, dict) or value.get("schema_version") != "1.0":
        return ["catalog must use schema_version 1.0"]
    plugins = value.get("plugins")
    if not isinstance(plugins, list):
        return ["plugins must be a list"]
    seen: set[tuple[str, str]] = set()
    for index, plugin in enumerate(plugins):
        label = f"plugins[{index}]"
        if not isinstance(plugin, dict):
            errors.append(f"{label} must be an object")
            continue
        plugin_id = plugin.get("id")
        version = plugin.get("version")
        if not isinstance(plugin_id, str) or not _ID.fullmatch(plugin_id):
            errors.append(f"{label}.id is invalid")
        try:
            Version.parse(str(version))
        except ValueError:
            errors.append(f"{label}.version is invalid")
        identity = (str(plugin_id), str(version))
        if identity in seen:
            errors.append(f"{label} duplicates {identity[0]} {identity[1]}")
        seen.add(identity)
        try:
            Version.parse(str(plugin.get("api_version")))
        except ValueError:
            errors.append(f"{label}.api_version is invalid")
        capabilities = plugin.get("capabilities")
        if (
            not isinstance(capabilities, list)
            or not capabilities
            or any(item not in _CAPABILITIES for item in capabilities)
        ):
            errors.append(f"{label}.capabilities is invalid")
        source_url = plugin.get("source_url")
        if not isinstance(source_url, str) or urlsplit(source_url).scheme != "https":
            errors.append(f"{label}.source_url must use HTTPS")
        if not _COMMIT.fullmatch(str(plugin.get("source_commit", ""))):
            errors.append(f"{label}.source_commit must be a full Git commit")
        for field in ("name", "description", "publisher", "license"):
            if not isinstance(plugin.get(field), str) or not plugin[field].strip():
                errors.append(f"{label}.{field} must not be empty")
    return errors


def load_catalog(path: Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    errors = validate_catalog(value)
    if errors:
        raise ValueError("invalid plugin catalog: " + "; ".join(errors))
    return value


def compatible_plugins(
    catalog: dict[str, Any], api_version: str
) -> list[dict[str, Any]]:
    current = Version.parse(api_version)
    compatible = []
    for plugin in catalog["plugins"]:
        required = Version.parse(plugin["api_version"])
        if required.major == current.major and required <= current:
            compatible.append(dict(plugin))
    return sorted(
        compatible, key=lambda item: (item["id"], Version.parse(item["version"]))
    )
