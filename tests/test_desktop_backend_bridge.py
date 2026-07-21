import base64
from io import StringIO
import json
from pathlib import Path
import threading

import pytest

from titan_decoder.desktop_ui import debian_bridge
from titan_decoder.desktop_ui.debian_services import DebianWorkbenchServices
from titan_decoder.workbench_ui.models import AnalysisSnapshot


def test_bridge_emits_progress_and_result(monkeypatch, capsys):
    class FakeServices:
        def __init__(self):
            self.callback = None

        def set_progress_callback(self, callback):
            self.callback = callback

        def update_state(self, **_changes):
            return None

        def analyze(self, data, source_name):
            assert data == b"evidence"
            assert source_name == "sample.bin"
            self.callback({"stage": "analysis", "percent": 50})
            return AnalysisSnapshot(
                source_name=source_name,
                source_size=len(data),
                decoded_output=b"decoded",
            )

    request = {
        "operation": "analyze",
        "source_name": "sample.bin",
        "data_base64": base64.b64encode(b"evidence").decode("ascii"),
    }
    monkeypatch.setattr(debian_bridge, "WorkbenchServices", FakeServices)
    monkeypatch.setattr(debian_bridge.sys, "stdin", StringIO(json.dumps(request)))

    debian_bridge.main()

    events = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert events[0] == {
        "type": "progress",
        "event": {"stage": "analysis", "percent": 50},
    }
    assert events[-1]["type"] == "result"
    assert base64.b64decode(events[-1]["payload"]["decoded_output_base64"]) == b"decoded"


def test_debian_service_routes_manual_decoder_to_backend(monkeypatch):
    service = DebianWorkbenchServices()
    seen = {}
    monkeypatch.setattr(service, "_ensure_compatible", lambda: None)

    def request(payload):
        seen.update(payload)
        return {
            "source_name": "sample.bin",
            "source_size": 3,
            "decoded_output_base64": base64.b64encode(b"ok").decode("ascii"),
            "decoder_success": True,
        }

    monkeypatch.setattr(service, "_request", request)
    snapshot = service.run_decoder(4, b"abc", "sample.bin")

    assert seen["operation"] == "run_decoder"
    assert seen["index"] == 4
    assert base64.b64decode(seen["data_base64"]) == b"abc"
    assert snapshot.decoded_output == b"ok"


def test_debian_service_rejects_protocol_major_mismatch(monkeypatch):
    service = DebianWorkbenchServices()
    monkeypatch.setattr(
        service,
        "capabilities",
        lambda **_kwargs: {"protocol_version": "2.0", "manual_decoders": []},
    )
    monkeypatch.setattr(
        service,
        "capabilities_local",
        lambda: {"protocol_version": "1.0", "manual_decoders": []},
    )

    with pytest.raises(RuntimeError, match="protocol is incompatible"):
        service._ensure_compatible()


def test_debian_service_rejects_decoder_inventory_mismatch(monkeypatch):
    service = DebianWorkbenchServices()
    monkeypatch.setattr(
        service,
        "capabilities",
        lambda **_kwargs: {"protocol_version": "1.0", "manual_decoders": ["A"]},
    )
    monkeypatch.setattr(
        service,
        "capabilities_local",
        lambda: {"protocol_version": "1.0", "manual_decoders": ["B"]},
    )

    with pytest.raises(RuntimeError, match="decoder inventory"):
        service._ensure_compatible()


def test_engine_progress_and_preflight_cancellation(tmp_path):
    from titan_decoder.config import Config
    from titan_decoder.core.engine import TitanEngine

    config = Config(tmp_path / "missing.json")
    events = []
    cancel = threading.Event()
    engine = TitanEngine(config, progress_callback=events.append, cancel_event=cancel)
    cancel.set()

    report = engine.run_analysis(b"ordinary text")

    assert report["analysis_outcome"]["status"] == "limited"
    assert "analysis_cancelled" in report["analysis_outcome"]["limitations"]
    assert events[0]["stage"] == "initializing"
    assert events[-1]["stage"] == "core_complete"
    assert all(0 <= event["percent"] <= 100 for event in events)


def test_debian_service_routes_deep_scan_to_backend(monkeypatch):
    service = DebianWorkbenchServices()
    seen = {}
    monkeypatch.setattr(service, "_ensure_compatible", lambda: None)

    def request(payload):
        seen.update(payload)
        return {"analyzed_count": 2, "results": []}

    monkeypatch.setattr(service, "_request", request)
    result = service.deep_scan_path(
        Path(r"C:\Evidence"), quarantine_malicious=True
    )

    assert result["analyzed_count"] == 2
    assert seen["operation"] == "deep_scan_path"
    assert seen["path"] == "/mnt/c/Evidence"
    assert seen["quarantine_malicious"] is True
