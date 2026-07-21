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
    services.set_progress_callback(
        lambda event: print(
            json.dumps({"type": "progress", "event": event}, separators=(",", ":")),
            flush=True,
        )
    )
    state = request.get("state") or {}
    services.update_state(
        profile=str(state.get("profile", "fast")),
        offline=bool(state.get("offline", True)),
        aggressive=bool(state.get("aggressive", False)),
    )

    operation = request.get("operation")
    if operation == "capabilities":
        payload = services.capabilities()
    elif operation == "analyze":
        data = base64.b64decode(request.get("data_base64", ""), validate=True)
        snapshot = services.analyze(data, str(request.get("source_name", "input")))
        payload = _snapshot_payload(snapshot)
    elif operation == "analyze_path":
        snapshot = services.analyze_path(Path(str(request["path"])))
        payload = _snapshot_payload(snapshot)
    elif operation == "run_decoder":
        data = base64.b64decode(request.get("data_base64", ""), validate=True)
        snapshot = services.run_decoder(
            int(request["index"]),
            data,
            str(request.get("source_name", "input")),
        )
        payload = _snapshot_payload(snapshot)
    elif operation == "deep_scan_path":
        payload = services.deep_scan_path(
            Path(str(request["path"])),
            quarantine_malicious=bool(request.get("quarantine_malicious", False)),
        )
    else:
        raise ValueError(f"Unsupported desktop bridge operation: {operation!r}")

    print(
        json.dumps({"type": "result", "payload": payload}, separators=(",", ":")),
        flush=True,
    )


if __name__ == "__main__":  # pragma: no cover - subprocess entry point
    main()
