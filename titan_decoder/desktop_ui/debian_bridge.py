"""Small JSON bridge used by the native Windows desktop frontend.

The bridge is launched inside Debian through ``wsl.exe``.  Keeping the
transport deliberately tiny lets Windows receive Explorer drag events while
Titan's actual analysis still runs in the user's Debian environment.
"""

from __future__ import annotations

import base64
from dataclasses import asdict
import json
from pathlib import Path
import sys
from typing import Any

from titan_decoder.workbench_ui.services import WorkbenchServices


def _snapshot_payload(snapshot: Any) -> dict[str, Any]:
    payload = asdict(snapshot)
    decoded = payload.get("decoded_output")
    if isinstance(decoded, bytes):
        payload["decoded_output_base64"] = base64.b64encode(decoded).decode("ascii")
        payload["decoded_output"] = None
    return payload


def main() -> None:
    request = json.load(sys.stdin)
    services = WorkbenchServices()
    state = request.get("state") or {}
    services.update_state(
        profile=str(state.get("profile", "fast")),
        offline=bool(state.get("offline", True)),
        aggressive=bool(state.get("aggressive", False)),
    )

    operation = request.get("operation")
    if operation == "analyze":
        data = base64.b64decode(request.get("data_base64", ""), validate=True)
        snapshot = services.analyze(data, str(request.get("source_name", "input")))
    elif operation == "analyze_path":
        snapshot = services.analyze_path(Path(str(request["path"])))
    else:
        raise ValueError(f"Unsupported desktop bridge operation: {operation!r}")

    json.dump(_snapshot_payload(snapshot), sys.stdout, separators=(",", ":"))


if __name__ == "__main__":  # pragma: no cover - subprocess entry point
    main()
