from titan_decoder.workbench_ui.services import WorkbenchServices


def test_service_exposes_decoder_inventory():
    services = WorkbenchServices()
    assert services.decoder_count() >= 10
    assert services.engine_version()


def test_report_count_handles_missing_directory(tmp_path):
    services = WorkbenchServices()
    assert services.report_count(tmp_path / "missing") == 0
