import json
from pathlib import Path

from titan_decoder import cli
from titan_decoder.config import Config
from titan_decoder.core.calibration import CalibrationRunner


CORPUS = Path(__file__).parent / "fixtures" / "calibration" / "decoder-analyzer-v1.json"


def test_bundled_decoder_analyzer_calibration_passes_quality_gate():
    report = CalibrationRunner().run(CORPUS)

    assert report["case_count"] == 27
    assert report["skipped_count"] == 0
    assert report["aggregate"]["precision"] == 1.0
    assert report["aggregate"]["recall"] == 1.0
    assert report["quality_gate"]["passed"] is True
    assert report["components"]["decoder:ASCII85"]["true_positive"] == 1
    assert report["components"]["analyzer:OfficeOOXML"]["true_negative"] == 1
    assert report["components"]["analyzer:RTF"]["true_positive"] == 1
    assert report["components"]["analyzer:MSI"]["true_negative"] == 1
    assert report["components"]["analyzer:OneNote"]["true_positive"] == 1


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


def test_cli_calibration_writes_report(tmp_path, capsys):
    output = tmp_path / "calibration-report.json"
    args = cli.build_parser().parse_args(
        ["--calibrate", str(CORPUS), "--calibration-out", str(output)]
    )

    assert cli.handle_info_commands(args, Config(tmp_path / "missing.json")) == 0
    assert json.loads(output.read_text(encoding="utf-8"))["quality_gate"]["passed"]
    assert json.loads(capsys.readouterr().out)["case_count"] == 27
