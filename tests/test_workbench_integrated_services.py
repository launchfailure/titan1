from titan_decoder.workbench_ui.services import WorkbenchServices


def test_decoder_inventory_is_real():
    services = WorkbenchServices()
    rows = services.decoder_rows()
    assert len(rows) >= 20
    assert any(label == "Base64" for _, label, _ in rows)


def test_system_metrics_have_expected_fields():
    metrics = WorkbenchServices().system_metrics()
    assert set(metrics) == {"cpu", "memory", "workers", "disk"}
