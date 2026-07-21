"""Windows frontend adapter that delegates analysis to Debian through WSL."""

from __future__ import annotations

import base64
from dataclasses import fields
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
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

    def _state_payload(self) -> dict[str, Any]:
        return {
            "profile": self.state.profile,
            "offline": self.state.offline,
            "aggressive": self.state.aggressive,
        }

    def _request(self, payload: dict[str, Any]) -> AnalysisSnapshot:
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
        completed = subprocess.run(
            command,
            input=json.dumps(payload),
            text=True,
            capture_output=True,
            timeout=int(self.config.get("analysis_timeout_seconds", 300)) + 30,
            creationflags=creation_flags,
            check=False,
        )
        if completed.returncode:
            detail = completed.stderr.strip() or completed.stdout.strip()
            raise RuntimeError(
                "The Debian analysis backend failed"
                + (f": {detail}" if detail else ".")
            )
        try:
            response = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                "The Debian backend returned an invalid response."
            ) from exc

        decoded = response.pop("decoded_output_base64", None)
        if decoded is not None:
            response["decoded_output"] = base64.b64decode(decoded)
        response["batch_errors"] = tuple(response.get("batch_errors") or ())
        valid_fields = {item.name for item in fields(AnalysisSnapshot)}
        return AnalysisSnapshot(
            **{key: value for key, value in response.items() if key in valid_fields}
        )

    def analyze(self, data: bytes, source_name: str) -> AnalysisSnapshot:
        return self._request(
            {
                "operation": "analyze",
                "state": self._state_payload(),
                "source_name": source_name,
                "data_base64": base64.b64encode(data).decode("ascii"),
            }
        )

    def analyze_path(self, path: Path) -> AnalysisSnapshot:
        snapshot = self._request(
            {
                "operation": "analyze_path",
                "state": self._state_payload(),
                "path": windows_path_to_wsl(path),
            }
        )
        # Keep a local copy so the native frontend's Recent Samples action can
        # reload the latest Debian result without another bridge call.
        self.save_report(snapshot)
        return snapshot


def desktop_services() -> WorkbenchServices:
    """Select the Debian bridge only for the native Windows frontend."""
    backend = os.environ.get("TITAN_DESKTOP_BACKEND", "debian").lower()
    if os.name == "nt" and backend == "debian":
        distribution = os.environ.get("TITAN_WSL_DISTRIBUTION", "Debian")
        return DebianWorkbenchServices(distribution)
    return WorkbenchServices()
