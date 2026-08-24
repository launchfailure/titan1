import json
from pathlib import Path

from titan_decoder import cli
from titan_decoder.config import Config
from titan_decoder.core.calibration import CalibrationRunner


CORPUS = Path(__file__).parent / "fixtures" / "calibration" / "decoder-analyzer-v1.json"


def test_bundled_decoder_analyzer_calibration_passes_quality_gate():
    report = CalibrationRunner().run(CORPUS)

    assert report["case_count"] == 78
    assert report["skipped_count"] == 0
    assert report["aggregate"]["precision"] == 1.0
    assert report["aggregate"]["recall"] == 1.0
    assert report["recognition_aggregate"]["precision"] == 1.0
    assert report["recognition_aggregate"]["recall"] == 1.0
    assert report["registry_coverage"]["live_builtin_count"] == 39
    assert report["registry_coverage"]["covered_count"] == 39
    assert report["registry_coverage"]["missing_positive"] == []
    assert report["registry_coverage"]["missing_negative"] == []
    assert report["quality_gate"]["passed"] is True
    assert report["components"]["decoder:ASCII85"]["true_positive"] == 1
    assert report["components"]["analyzer:OfficeOOXML"]["true_negative"] == 1


def test_calibration_detects_output_regression(tmp_path):
    corpus = tmp_path / "regression.json"
    corpus.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "cases": [
                    {
                        "id": "wrong-output",
                        "kind": "decoder",
                        "component": "ASCII85",
                        "data_text": "<~87cURD_*#1Blmd$+T~>",
                        "expected_match": True,
                        "expected_output_sha256": "0" * 64,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    report = CalibrationRunner(Config(tmp_path / "missing.json")).run(corpus)

    assert report["aggregate"]["false_negative"] == 1
    assert report["quality_gate"]["passed"] is False


def test_registry_parity_reports_missing_live_component_slices(tmp_path):
    corpus = tmp_path / "partial.json"
    corpus.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "require_registry_parity": True,
                "cases": [
                    {
                        "id": "ascii85-positive-only",
                        "kind": "decoder",
                        "component": "ASCII85",
                        "data_text": "<~87cURD_*#1Blmd$+T~>",
                        "expected_match": True,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    report = CalibrationRunner(Config(tmp_path / "missing.json")).run(corpus)

    assert report["quality_gate"]["passed"] is False
    assert "decoder:Base64" in report["registry_coverage"]["missing_positive"]
    assert "decoder:ASCII85" in report["registry_coverage"]["missing_negative"]


def test_optional_dependency_skips_extraction_but_measures_recognition(tmp_path):
    corpus = tmp_path / "optional.json"
    corpus.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "cases": [
                    {
                        "id": "optional-ascii85",
                        "kind": "decoder",
                        "component": "ASCII85",
                        "data_text": "<~87cURD_*#1Blmd$+T~>",
                        "expected_recognition": True,
                        "expected_match": True,
                        "required_modules": ["titan_test_module_that_does_not_exist"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    report = CalibrationRunner(Config(tmp_path / "missing.json")).run(corpus)

    assert report["recognition_aggregate"]["true_positive"] == 1
    assert report["components"] == {}
    assert report["dependency_skips"] == [
        {
            "id": "optional-ascii85",
            "component": "decoder:ASCII85",
            "missing_modules": ["titan_test_module_that_does_not_exist"],
        }
    ]
    assert report["quality_gate"]["passed"] is True


def test_invalid_negative_case_cannot_earn_quality_credit(tmp_path):
    corpus = tmp_path / "invalid-negative.json"
    corpus.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "cases": [
                    {
                        "id": "invalid-negative",
                        "kind": "decoder",
                        "component": "ASCII85",
                        "data_base64": "not-valid-base64!",
                        "expected_match": False,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    report = CalibrationRunner(Config(tmp_path / "missing.json")).run(corpus)

    assert report["quality_gate"]["passed"] is False
    assert any(
        "invalid-negative: evaluation error" in str(failure)
        for failure in report["quality_gate"]["failures"]
    )


def test_unknown_component_cannot_be_silently_skipped(tmp_path):
    corpus = tmp_path / "unknown-component.json"
    corpus.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "cases": [
                    {
                        "id": "known",
                        "kind": "decoder",
                        "component": "ASCII85",
                        "data_text": "ordinary prose is not ascii85",
                        "expected_match": False,
                    },
                    {
                        "id": "unknown",
                        "kind": "decoder",
                        "component": "NotARealDecoder",
                        "data_text": "payload",
                        "expected_match": False,
                    },
                ],
            }
        ),
        encoding="utf-8",
    )

    report = CalibrationRunner(Config(tmp_path / "missing.json")).run(corpus)

    assert report["skipped_count"] == 1
    assert report["quality_gate"]["passed"] is False
    assert any(
        "unknown or unavailable component decoder:NotARealDecoder" in str(failure)
        for failure in report["quality_gate"]["failures"]
    )


def test_cli_calibration_writes_report(tmp_path, capsys):
    output = tmp_path / "calibration-report.json"
    args = cli.build_parser().parse_args(
        ["--calibrate", str(CORPUS), "--calibration-out", str(output)]
    )

    assert cli.handle_info_commands(args, Config(tmp_path / "missing.json")) == 0
    assert json.loads(output.read_text(encoding="utf-8"))["quality_gate"]["passed"]
    assert json.loads(capsys.readouterr().out)["case_count"] == 78
