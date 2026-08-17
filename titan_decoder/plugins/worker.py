"""One-request worker used by isolated manifest-plugin proxies."""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import socket
import sys
from typing import Any, Mapping

from .contracts import (
    DetectionPlugin,
    ExtractorPlugin,
    PluginAnalyzer,
    PluginContext,
    PluginDecoder,
    ReportPlugin,
)
from .manifest import PluginManifest
from .registry import _instantiate_entry_point


def _apply_resource_limits(limits: Mapping[str, Any]) -> None:
    if os.name == "nt":
        return
    try:
        import resource

        resource_module: Any = resource
        memory = int(limits.get("max_memory_mb", 512)) * 1024 * 1024
        output = int(limits.get("max_output_bytes", 16 * 1024 * 1024))
        resource_module.setrlimit(resource_module.RLIMIT_AS, (memory, memory))
        resource_module.setrlimit(resource_module.RLIMIT_FSIZE, (output, output))
        resource_module.setrlimit(resource_module.RLIMIT_CORE, (0, 0))
    except (ImportError, OSError, ValueError):
        return


def _block_network() -> None:
    def denied(*_args: Any, **_kwargs: Any) -> Any:
        raise PermissionError("network access denied by Titan plugin policy")

    socket_module: Any = socket
    socket_module.socket = denied
    socket_module.create_connection = denied
    socket_module.getaddrinfo = denied


def _context(value: Any) -> PluginContext:
    value = value if isinstance(value, dict) else {}
    directory = value.get("working_directory")
    return PluginContext(
        config=value.get("config") if isinstance(value.get("config"), dict) else {},
        offline=bool(value.get("offline", True)),
        max_input_bytes=int(value.get("max_input_bytes", 100 * 1024 * 1024)),
        max_output_bytes=int(value.get("max_output_bytes", 16 * 1024 * 1024)),
        max_children=int(value.get("max_children", 100)),
        working_directory=Path(str(directory)) if directory else None,
    )


def _bytes(payload: Mapping[str, Any]) -> bytes:
    return base64.b64decode(str(payload.get("data") or ""), validate=True)


def _metadata(instance: Any) -> dict[str, Any]:
    capabilities = []
    if isinstance(instance, PluginDecoder):
        capabilities.append("decoder")
    if isinstance(instance, PluginAnalyzer):
        capabilities.append("analyzer")
    if isinstance(instance, DetectionPlugin):
        capabilities.append("detection")
    if isinstance(instance, ExtractorPlugin):
        capabilities.append("extractor")
    if isinstance(instance, ReportPlugin):
        capabilities.append("report")
    return {
        "name": str(instance.name),
        "priority": int(getattr(instance, "priority", 0)),
        "capabilities": sorted(capabilities),
        "rule_ids": [str(value) for value in getattr(instance, "rule_ids", ())],
    }


def _invoke(instance: Any, request: Mapping[str, Any]) -> Any:
    operation = str(request.get("operation") or "")
    payload = request.get("payload")
    payload = payload if isinstance(payload, dict) else {}
    context = _context(request.get("context"))
    if operation == "metadata":
        return _metadata(instance)
    if operation == "can_decode":
        return instance.can_decode(_bytes(payload), context)
    if operation == "decode":
        value = instance.decode(_bytes(payload), context)
        data, success = value
        metadata = getattr(value, "metadata", {})
        return {
            "data": base64.b64encode(data).decode("ascii"),
            "success": bool(success),
            "metadata": dict(metadata),
        }
    if operation == "can_analyze":
        return instance.can_analyze(_bytes(payload), context)
    if operation == "analyze":
        result = []
        for value in instance.analyze(_bytes(payload), context):
            name, data = value
            result.append(
                {
                    "name": str(name),
                    "data": base64.b64encode(data).decode("ascii"),
                    "metadata": dict(getattr(value, "metadata", {})),
                }
            )
        return result
    if operation == "detect":
        report = payload.get("report")
        iocs = payload.get("iocs")
        values = instance.detect(
            report if isinstance(report, dict) else {},
            iocs if isinstance(iocs, dict) else {},
            context,
        )
        return [value.to_dict() for value in values]
    if operation == "can_extract":
        return instance.can_extract(_bytes(payload), context)
    if operation == "extract":
        return [value.to_dict() for value in instance.extract(_bytes(payload), context)]
    if operation == "build_sections":
        report = payload.get("report")
        return [
            value.to_dict()
            for value in instance.build_sections(
                report if isinstance(report, dict) else {}, context
            )
        ]
    raise ValueError(f"unsupported plugin worker operation: {operation}")


def main() -> None:
    plugin_path = Path(sys.argv[1]).resolve()
    request = json.load(sys.stdin)
    limits = request.get("limits")
    limits = limits if isinstance(limits, dict) else {}
    _apply_resource_limits(limits)
    manifest_value = request.get("manifest")
    if not isinstance(manifest_value, dict):
        raise ValueError("plugin worker request has no manifest")
    manifest = PluginManifest.from_dict(manifest_value)
    if bool(request.get("offline", True)) or "network" not in manifest.permissions:
        _block_network()
    instance = _instantiate_entry_point(plugin_path, manifest)
    result = _invoke(instance, request)
    encoded = json.dumps({"ok": True, "result": result}, separators=(",", ":"))
    limit = int(limits.get("max_output_bytes", 16 * 1024 * 1024))
    if len(encoded.encode("utf-8")) > limit:
        raise ValueError("plugin result exceeded the configured output limit")
    print(encoded)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(
            json.dumps(
                {"ok": False, "error": f"{type(exc).__name__}: {exc}"},
                separators=(",", ":"),
            )
        )
