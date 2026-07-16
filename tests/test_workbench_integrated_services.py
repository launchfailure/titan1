import json

import pytest

from titan_decoder.workbench_ui.models import AnalysisSnapshot
from titan_decoder.workbench_ui import services as services_module
from titan_decoder.workbench_ui.services import WorkbenchServices


def test_decoder_inventory_is_real():
    services = WorkbenchServices()
    rows = services.decoder_rows()
    assert len(rows) >= 20
    assert any(label == "Base64" for _, label, _ in rows)


def test_system_metrics_have_expected_fields():
    metrics = WorkbenchServices().system_metrics()
    assert set(metrics) == {"cpu", "memory", "workers", "disk"}


def test_system_metrics_work_without_unix_resource_module(monkeypatch):
    monkeypatch.setattr(services_module, "_resource", None)
    assert WorkbenchServices().system_metrics()["memory"] == "n/a"


def test_long_files_are_rejected_before_an_unbounded_read(tmp_path):
    source = tmp_path / "large.bin"
    source.write_bytes(b"ABCD")
    services = WorkbenchServices()
    services.config.set("max_data_size", 3)

    with pytest.raises(ValueError, match="exceeds the 3-byte input limit"):
        services.read_file(source)


def test_directory_reports_do_not_collide_on_duplicate_basenames(tmp_path, monkeypatch):
    source = tmp_path / "source"
    reports = tmp_path / "reports"
    (source / "a").mkdir(parents=True)
    (source / "b").mkdir(parents=True)
    (source / "a" / "sample.bin").write_bytes(b"A")
    (source / "b" / "sample.bin").write_bytes(b"B")

    services = WorkbenchServices()
    services.update_state(reports_dir=reports)

    def fake_analyze(data, source_name):
        return AnalysisSnapshot(
            source_name=source_name,
            source_size=len(data),
            report={"payload": data.decode("ascii")},
        )

    monkeypatch.setattr(services, "analyze", fake_analyze)
    snapshot = services.analyze_path(source)
    outputs = sorted(reports.glob("*.json"))

    assert snapshot.batch_succeeded == snapshot.batch_total == 2
    assert len(outputs) == 2
    assert outputs[0].name != outputs[1].name
    assert {json.loads(path.read_text())["payload"] for path in outputs} == {"A", "B"}


def test_load_report_rejects_non_object_json(tmp_path):
    report = tmp_path / "invalid.json"
    report.write_text("[]", encoding="utf-8")

    with pytest.raises(ValueError, match="JSON object"):
        WorkbenchServices().load_report(report)
