"""Windows frontend adapter that delegates analysis to Debian through WSL."""

from __future__ import annotations

import base64
from dataclasses import fields
import json
import os
from pathlib import Path
import queue
import re
import shlex
import subprocess
import threading
import time
from typing import Any

from titan_decoder.workbench_ui.models import AnalysisSnapshot
from titan_decoder.workbench_ui.services import WorkbenchServices


def windows_path_to_wsl(value: str | Path) -> str:
    """Translate an ordinary Windows drive path into its Debian WSL mount."""
    raw = str(value)
    match = re.match(r"^(?P<drive>[A-Za-z]):[\\/](?P<tail>.*)$", raw, re.DOTALL)
    if match:
        drive = match.group("drive").lower()
        tail = match.group("tail").replace("\\", "/")
        return f"/mnt/{drive}/{tail}"
    return raw.replace("\\", "/")


class DebianWorkbenchServices(WorkbenchServices):
    """Use local presentation helpers but execute analyses inside Debian."""

    def __init__(self, distribution: str = "Debian"):
        super().__init__()
        self.distribution = distribution
        repository = Path(__file__).resolve().parents[2]
        self.debian_repository = windows_path_to_wsl(repository)
        self._process_lock = threading.Lock()
        self._process: subprocess.Popen[str] | None = None
        self._capabilities_cache: dict[str, Any] | None = None
        self._local_capabilities_cache: dict[str, Any] | None = None

    def _state_payload(self) -> dict[str, Any]:
        return {
            "profile": self.state.profile,
            "offline": self.state.offline,
            "aggressive": self.state.aggressive,
        }

    def _request(self, payload: dict[str, Any]) -> dict[str, Any]:
        command_text = (
            f"cd {shlex.quote(self.debian_repository)} && "
            ".venv/bin/python -m titan_decoder.desktop_ui.debian_bridge"
        )
        command = [
            "wsl.exe",
            "-d",
            self.distribution,
            "--",
            "bash",
            "-lc",
            command_text,
        ]
        creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            creationflags=creation_flags,
        )
        with self._process_lock:
            self._process = process
        response: dict[str, Any] | None = None
        protocol_noise: list[str] = []
        stderr_lines: list[str] = []
        output_queue: queue.Queue[str | None] = queue.Queue()

        def read_stdout() -> None:
            assert process.stdout is not None
            try:
                for line in process.stdout:
                    output_queue.put(line)
            finally:
                output_queue.put(None)

        def read_stderr() -> None:
            assert process.stderr is not None
            for line in process.stderr:
                if len(stderr_lines) < 100:
                    stderr_lines.append(line.rstrip()[:1000])

        stdout_thread = threading.Thread(target=read_stdout, daemon=True)
        stderr_thread = threading.Thread(target=read_stderr, daemon=True)
        stdout_thread.start()
        stderr_thread.start()
        timeout = int(self.config.get("analysis_timeout_seconds", 300)) + 30
        deadline = time.monotonic() + timeout
        try:
            assert process.stdin is not None
            process.stdin.write(json.dumps(payload))
            process.stdin.close()
            stdout_closed = False
            while not stdout_closed:
                if self.cancel_event.is_set():
                    process.terminate()
                    raise RuntimeError("Analysis cancelled.")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    process.kill()
                    raise RuntimeError("The Debian analysis backend timed out.")
                try:
                    line = output_queue.get(timeout=min(0.1, remaining))
                except queue.Empty:
                    if process.poll() is not None and not stdout_thread.is_alive():
                        break
                    continue
                if line is None:
                    stdout_closed = True
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    if len(protocol_noise) < 10:
                        protocol_noise.append(line.strip()[:500])
                    continue
                if not isinstance(event, dict):
                    continue
                if event.get("type") == "progress":
                    self._progress(dict(event.get("event") or {}))
                elif event.get("type") == "result" and isinstance(
                    event.get("payload"), dict
                ):
                    response = dict(event["payload"])
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                process.kill()
                raise RuntimeError("The Debian analysis backend timed out.")
            return_code = process.wait(timeout=remaining)
            stderr_thread.join(timeout=1)
            stderr = "\n".join(stderr_lines).strip()
        except subprocess.TimeoutExpired as exc:
            process.kill()
            process.wait()
            raise RuntimeError("The Debian analysis backend timed out.") from exc
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            with self._process_lock:
                if self._process is process:
                    self._process = None
        if self.cancel_event.is_set():
            raise RuntimeError("Analysis cancelled.")
        if return_code:
            detail = stderr or "; ".join(protocol_noise)
            raise RuntimeError(
                "The Debian analysis backend failed"
                + (f": {detail}" if detail else ".")
            )
        if response is None:
            raise RuntimeError(
                "The Debian backend returned no valid result."
                + (
                    f" Protocol output: {'; '.join(protocol_noise)}"
                    if protocol_noise
                    else ""
                )
            )
        return response

    @staticmethod
    def _snapshot(response: dict[str, Any]) -> AnalysisSnapshot:
        response = dict(response)

        decoded = response.pop("decoded_output_base64", None)
        if decoded is not None:
            response["decoded_output"] = base64.b64decode(decoded)
        response["batch_errors"] = tuple(response.get("batch_errors") or ())
        valid_fields = {item.name for item in fields(AnalysisSnapshot)}
        return AnalysisSnapshot(
            **{key: value for key, value in response.items() if key in valid_fields}
        )

    def cancel_current(self) -> None:
        super().cancel_current()
        with self._process_lock:
            process = self._process
        if process is not None and process.poll() is None:
            process.terminate()

    def capabilities(self, *, refresh: bool = False) -> dict[str, Any]:
        if self._capabilities_cache is None or refresh:
            self.cancel_event.clear()
            self._capabilities_cache = self._request({"operation": "capabilities"})
        return dict(self._capabilities_cache)

    def _ensure_compatible(self) -> None:
        capabilities = self.capabilities()
        protocol = str(capabilities.get("protocol_version") or "")
        local_protocol = str(self.capabilities_local()["protocol_version"])
        if protocol.split(".", 1)[0] != local_protocol.split(".", 1)[0]:
            raise RuntimeError(
                "The Debian backend protocol is incompatible with this Windows UI "
                f"({protocol or 'unknown'} vs {local_protocol}). Update both copies "
                "of Titan before analyzing evidence."
            )
        remote_decoders = capabilities.get("manual_decoders")
        local_decoders = self.capabilities_local()["manual_decoders"]
        if remote_decoders != local_decoders:
            raise RuntimeError(
                "The Debian backend decoder inventory does not match the Windows UI. "
                "Update the Debian environment before running a decoder."
            )

    def capabilities_local(self) -> dict[str, Any]:
        """Return the Windows-side contract without invoking the Debian bridge."""
        if self._local_capabilities_cache is None:
            self._local_capabilities_cache = super().capabilities()
        return dict(self._local_capabilities_cache)

    def analyze(self, data: bytes, source_name: str) -> AnalysisSnapshot:
        self.cancel_event.clear()
        self._ensure_compatible()
        return self._snapshot(
            self._request(
                {
                    "operation": "analyze",
                    "state": self._state_payload(),
                    "source_name": source_name,
                    "data_base64": base64.b64encode(data).decode("ascii"),
                }
            )
        )

    def analyze_path(self, path: Path) -> AnalysisSnapshot:
        self.cancel_event.clear()
        self._ensure_compatible()
        snapshot = self._snapshot(
            self._request(
                {
                    "operation": "analyze_path",
                    "state": self._state_payload(),
                    "path": windows_path_to_wsl(path),
                }
            )
        )
        # Keep a local copy so the native frontend's Recent Samples action can
        # reload the latest Debian result without another bridge call.
        self.save_report(snapshot)
        return snapshot

    def run_decoder(
        self, index: int, data: bytes, source_name: str
    ) -> AnalysisSnapshot:
        self.cancel_event.clear()
        self._ensure_compatible()
        return self._snapshot(
            self._request(
                {
                    "operation": "run_decoder",
                    "state": self._state_payload(),
                    "index": index,
                    "source_name": source_name,
                    "data_base64": base64.b64encode(data).decode("ascii"),
                }
            )
        )

    def deep_scan_path(
        self,
        path: Path,
        *,
        quarantine_malicious: bool = False,
    ) -> dict[str, Any]:
        self.cancel_event.clear()
        self._ensure_compatible()
        return self._request(
            {
                "operation": "deep_scan_path",
                "state": self._state_payload(),
                "path": windows_path_to_wsl(path),
                "quarantine_malicious": quarantine_malicious,
            }
        )


def desktop_services() -> WorkbenchServices:
    """Select the Debian bridge only for the native Windows frontend."""
    backend = os.environ.get("TITAN_DESKTOP_BACKEND", "debian").lower()
    if os.name == "nt" and backend == "debian":
        distribution = os.environ.get("TITAN_WSL_DISTRIBUTION", "Debian")
        return DebianWorkbenchServices(distribution)
    return WorkbenchServices()
