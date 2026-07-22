import pytest

from titan_decoder.workbench_ui.services import WorkbenchServices


def test_service_exposes_decoder_inventory():
    services = WorkbenchServices()
    assert services.decoder_count() >= 10
    assert services.engine_version()


def test_report_count_handles_missing_directory(tmp_path):
    services = WorkbenchServices()
    assert services.report_count(tmp_path / "missing") == 0


def test_backend_capabilities_advertise_extended_contract(tmp_path):
    from titan_decoder.config import Config

    services = WorkbenchServices(Config(tmp_path / "missing.json"))
    capabilities = services.capabilities()

    assert capabilities["protocol_version"] == "1.0"
    assert capabilities["features"]["deep_scan"] is True
    assert capabilities["features"]["cancellation"] is True
    assert capabilities["features"]["isolated_manifest_plugins"] is True
    assert "ASCII85" in capabilities["decoders"]
    assert "OfficeOOXML" in capabilities["analyzers"]
    assert (
        capabilities["optional_format_support"]["modules"]
        == capabilities["optional_formats"]
    )


def test_manual_optional_decoder_reports_a_missing_library(monkeypatch):
    services = WorkbenchServices()
    index = next(
        index
        for index, choice in enumerate(services.registry)
        if choice.label == "Brotli"
    )
    monkeypatch.setattr(
        "titan_decoder.workbench_ui.services.optional_format_status",
        lambda: {
            "modules": {"brotli": False},
            "ready": False,
            "missing": ["brotli"],
        },
    )

    with pytest.raises(RuntimeError, match="formats"):
        services.run_decoder(index, b"brotli:not-compressed", "sample.bin")
