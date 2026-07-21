"""Out-of-process proxies for manifest plugins.

Each call starts a short-lived Python worker, exchanges one bounded JSON
request, and exits. A crash, global mutation, or ordinary exception in a
third-party plugin therefore cannot corrupt Titan's analysis process.
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from typing import Any, Mapping

from .contracts import (
    AnalysisArtifact,
    AnalyzerPlugin,
    DecodeResult,
    DecoderPlugin,
    DetectionFinding,
    DetectionPlugin,
    PluginContext,
    ReportPlugin,
    ReportSection,
)
from .manifest import PluginManifest


def _worker_environment() -> dict[str, str]:
    allowed = {
        "COMSPEC",
        "HOME",
        "LANG",
        "LC_ALL",
        "LOCALAPPDATA",
        "PATH",
        "PATHEXT",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "WINDIR",
    }
    value = {key: item for key, item in os.environ.items() if key in allowed}
    value["PYTHONNOUSERSITE"] = "1"
    value["TITAN_PLUGIN_WORKER"] = "1"
    return value


class IsolatedPluginClient:
    """Invoke one manifest entry point through a bounded subprocess."""

    def __init__(
        self,
        path: Path,
        manifest: PluginManifest,
        *,
        offline: bool = True,
        timeout_seconds: int = 10,
        max_input_bytes: int = 100 * 1024 * 1024,
        max_output_bytes: int = 16 * 1024 * 1024,
        max_memory_mb: int = 512,
        max_children: int = 100,
    ):
        self.path = path.resolve()
        self.manifest = manifest
        self.offline = offline
        self.timeout_seconds = max(1, int(timeout_seconds))
        self.max_input_bytes = max(1, int(max_input_bytes))
        self.max_output_bytes = max(1024, int(max_output_bytes))
        self.max_memory_mb = max(64, int(max_memory_mb))
        self.max_children = max(1, int(max_children))

    def invoke(
        self,
        operation: str,
        payload: Mapping[str, Any] | None = None,
        context: PluginContext | None = None,
    ) -> Any:
        if self.offline and "network" in self.manifest.permissions:
            raise PermissionError(
                f"plugin {self.manifest.plugin_id} requests network access in offline mode"
            )
        context_payload = self._context_payload(context)
        request = {
            "operation": operation,
            "payload": dict(payload or {}),
            "context": context_payload,
            "manifest": self.manifest.to_dict(),
            "limits": {
                "max_input_bytes": self.max_input_bytes,
                "max_output_bytes": self.max_output_bytes,
                "max_memory_mb": self.max_memory_mb,
                "max_children": self.max_children,
            },
            "offline": self.offline,
        }
        encoded = json.dumps(request, separators=(",", ":")).encode("utf-8")
        if len(encoded) > self.max_input_bytes:
            raise ValueError("plugin request exceeded the configured input limit")
        response = self._run_worker(encoded)
        if not isinstance(response, dict):
            raise RuntimeError("plugin worker returned a non-object response")
        if response.get("ok") is not True:
            raise RuntimeError(
                str(response.get("error") or "plugin worker failed")[:1000]
            )
        return response.get("result")

    def _context_payload(self, context: PluginContext | None) -> dict[str, Any]:
        if context is None:
            context = PluginContext(
                offline=self.offline,
                max_input_bytes=self.max_input_bytes,
                max_output_bytes=self.max_output_bytes,
                max_children=self.max_children,
                working_directory=self.path,
            )
        can_read_config = "configuration" in self.manifest.permissions
        return {
            "config": dict(context.config) if can_read_config else {},
            "offline": bool(context.offline or self.offline),
            "max_input_bytes": min(context.max_input_bytes, self.max_input_bytes),
            "max_output_bytes": min(context.max_output_bytes, self.max_output_bytes),
            "max_children": min(context.max_children, self.max_children),
            "working_directory": str(context.working_directory or self.path),
        }

    def _run_worker(self, request: bytes) -> dict[str, Any]:
        command = [
            sys.executable,
            "-I",
            "-m",
            "titan_decoder.plugins.worker",
            str(self.path),
        ]
        creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        with tempfile.TemporaryFile() as input_file, tempfile.TemporaryFile() as output:
            input_file.write(request)
            input_file.seek(0)
            process = subprocess.Popen(
                command,
                stdin=input_file,
                stdout=output,
                stderr=output,
                cwd=self.path,
                env=_worker_environment(),
                creationflags=creation_flags,
            )
            deadline = time.monotonic() + self.timeout_seconds
            while process.poll() is None:
                if time.monotonic() >= deadline:
                    process.kill()
                    process.wait()
                    raise TimeoutError(
                        f"plugin {self.manifest.plugin_id} exceeded "
                        f"the {self.timeout_seconds}s timeout"
                    )
                if os.fstat(output.fileno()).st_size > self.max_output_bytes:
                    process.kill()
                    process.wait()
                    raise RuntimeError(
                        f"plugin {self.manifest.plugin_id} exceeded the output limit"
                    )
                time.sleep(0.01)
            size = os.fstat(output.fileno()).st_size
            output.seek(0)
            raw = output.read(min(size, self.max_output_bytes + 1))
        if len(raw) > self.max_output_bytes:
            raise RuntimeError(
                f"plugin {self.manifest.plugin_id} exceeded the output limit"
            )
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            detail = raw.decode("utf-8", errors="replace")[:500]
            raise RuntimeError(f"invalid plugin worker response: {detail}") from exc
        if not isinstance(value, dict):
            raise RuntimeError("invalid plugin worker response")
        return value


class _ProxyBase:
    def __init__(self, client: IsolatedPluginClient, metadata: Mapping[str, Any]):
        self._client = client
        self._name = str(metadata.get("name") or client.manifest.name)
        self._priority = int(metadata.get("priority") or 0)

    @property
    def name(self) -> str:
        return self._name

    @property
    def priority(self) -> int:
        return self._priority

    @priority.setter
    def priority(self, value: int) -> None:
        self._priority = int(value)


def _metadata_mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, dict) else {}


class IsolatedDecoderProxy(_ProxyBase, DecoderPlugin):
    def can_decode(self, data: bytes, context: PluginContext | None = None) -> bool:
        value = self._client.invoke(
            "can_decode", {"data": base64.b64encode(data).decode("ascii")}, context
        )
        if not isinstance(value, bool):
            raise TypeError("decoder can_decode returned a non-boolean value")
        return value

    def decode(self, data: bytes, context: PluginContext | None = None) -> DecodeResult:
        value = self._client.invoke(
            "decode", {"data": base64.b64encode(data).decode("ascii")}, context
        )
        if not isinstance(value, dict):
            raise TypeError("decoder returned an invalid result")
        decoded = base64.b64decode(str(value.get("data") or ""), validate=True)
        if len(decoded) > self._client.max_output_bytes:
            raise ValueError("decoder result exceeded the output limit")
        return DecodeResult(
            decoded,
            bool(value.get("success")),
            _metadata_mapping(value.get("metadata")),
        )


class IsolatedAnalyzerProxy(_ProxyBase, AnalyzerPlugin):
    def can_analyze(self, data: bytes, context: PluginContext | None = None) -> bool:
        value = self._client.invoke(
            "can_analyze", {"data": base64.b64encode(data).decode("ascii")}, context
        )
        if not isinstance(value, bool):
            raise TypeError("analyzer can_analyze returned a non-boolean value")
        return value

    def analyze(
        self, data: bytes, context: PluginContext | None = None
    ) -> list[AnalysisArtifact]:
        values = self._client.invoke(
            "analyze", {"data": base64.b64encode(data).decode("ascii")}, context
        )
        if not isinstance(values, list):
            raise TypeError("analyzer returned an invalid result")
        artifacts: list[AnalysisArtifact] = []
        total = 0
        for value in values[: self._client.max_children]:
            if not isinstance(value, dict):
                raise TypeError("analyzer returned an invalid artifact")
            data_value = base64.b64decode(str(value.get("data") or ""), validate=True)
            total += len(data_value)
            if total > self._client.max_output_bytes:
                raise ValueError("analyzer artifacts exceeded the output limit")
            artifacts.append(
                AnalysisArtifact(
                    str(value.get("name") or ""),
                    data_value,
                    _metadata_mapping(value.get("metadata")),
                )
            )
        return artifacts


class IsolatedDetectionProxy(_ProxyBase, DetectionPlugin):
    def __init__(self, client: IsolatedPluginClient, metadata: Mapping[str, Any]):
        super().__init__(client, metadata)
        self._rule_ids = tuple(str(value) for value in metadata.get("rule_ids") or ())

    @property
    def rule_ids(self) -> tuple[str, ...]:
        return self._rule_ids

    def detect(
        self,
        report: Mapping[str, Any],
        iocs: Mapping[str, Any],
        context: PluginContext | None = None,
    ) -> list[DetectionFinding]:
        values = self._client.invoke(
            "detect", {"report": dict(report), "iocs": dict(iocs)}, context
        )
        if not isinstance(values, list):
            raise TypeError("detection plugin returned an invalid result")
        return [
            DetectionFinding(
                rule_id=str(value.get("rule_id") or ""),
                name=str(value.get("name") or ""),
                description=str(value.get("description") or ""),
                severity=str(value.get("severity") or ""),
                attack_ids=tuple(value.get("attack_ids") or ()),
                evidence=tuple(value.get("evidence") or ()),
                metadata=_metadata_mapping(value.get("metadata")),
            )
            for value in values[: self._client.max_children]
            if isinstance(value, dict)
        ]


class IsolatedReportProxy(_ProxyBase, ReportPlugin):
    def build_sections(
        self,
        report: Mapping[str, Any],
        context: PluginContext | None = None,
    ) -> list[ReportSection]:
        values = self._client.invoke(
            "build_sections", {"report": dict(report)}, context
        )
        if not isinstance(values, list):
            raise TypeError("report plugin returned an invalid result")
        return [
            ReportSection(
                section_id=str(value.get("section_id") or ""),
                title=str(value.get("title") or ""),
                content=value.get("content"),
                order=int(value.get("order") or 100),
                formats=tuple(value.get("formats") or ("json",)),
                metadata=_metadata_mapping(value.get("metadata")),
            )
            for value in values[: self._client.max_children]
            if isinstance(value, dict)
        ]


def build_isolated_proxies(
    path: Path,
    manifest: PluginManifest,
    **limits: Any,
) -> tuple[list[Any], dict[str, Any]]:
    client = IsolatedPluginClient(path, manifest, **limits)
    metadata = client.invoke("metadata")
    if not isinstance(metadata, dict):
        raise TypeError("plugin metadata response is invalid")
    actual = set(metadata.get("capabilities") or ())
    declared = set(manifest.capabilities)
    if actual != declared:
        raise TypeError(
            f"entry point capabilities {sorted(actual)} do not match manifest "
            f"{sorted(declared)}"
        )
    proxies: list[Any] = []
    for capability in sorted(actual):
        proxy_type = {
            "decoder": IsolatedDecoderProxy,
            "analyzer": IsolatedAnalyzerProxy,
            "detection": IsolatedDetectionProxy,
            "report": IsolatedReportProxy,
        }[capability]
        proxies.append(proxy_type(client, metadata))
    return proxies, metadata
