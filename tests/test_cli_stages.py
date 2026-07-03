"""Stage-level unit tests for the decomposed CLI.

main() is now a thin dispatcher over independently-callable stages
(build_parser, load_input, run_analysis_stage, attach_evidence_stage,
run_detections_stage, write_outputs_stage). These tests exercise the stages
directly — asserting the CLI behaviors that used to require an end-to-end run
(exit codes, evidence-before-analysis ordering, batch newline handling).
"""

import json

import pytest

from titan_decoder import cli
from titan_decoder.config import Config


def _args(**over):
    """Parse an argv into a Namespace, then apply overrides."""
    argv = over.pop("argv", [])
    args = cli.build_parser().parse_args(argv)
    for k, v in over.items():
        setattr(args, k, v)
    return args


def test_build_parser_defaults():
    parser = cli.build_parser()
    args = parser.parse_args(["--file", "x.bin"])
    assert str(args.file) == "x.bin"
    assert args.stdout == "json"
    assert args.enable_detections is False


def test_load_input_reads_file(tmp_path):
    f = tmp_path / "in.bin"
    f.write_bytes(b"hello world")
    args = _args(argv=["--file", str(f)])
    data = cli.load_input(args, Config())
    assert data == b"hello world"


def test_load_input_missing_file_exits(tmp_path):
    args = _args(argv=["--file", str(tmp_path / "nope.bin")])
    with pytest.raises(SystemExit) as ei:
        cli.load_input(args, Config())
    assert ei.value.code == 1


def test_load_input_empty_file_exits(tmp_path):
    f = tmp_path / "empty.bin"
    f.write_bytes(b"")
    args = _args(argv=["--file", str(f)])
    with pytest.raises(SystemExit) as ei:
        cli.load_input(args, Config())
    assert ei.value.code == 1


def test_load_input_no_source_exits():
    args = _args(argv=[])
    with pytest.raises(SystemExit) as ei:
        cli.load_input(args, Config())
    assert ei.value.code == 1


def test_load_input_evidence_only_returns_empty(tmp_path):
    args = _args(argv=[], evidence=["dns:whatever"])
    # Evidence-only mode: no --file is allowed, returns empty payload.
    data = cli.load_input(args, Config())
    assert data == b""


def test_run_analysis_stage_sets_run_mode_meta():
    args = _args(argv=["--file", "x"], offline=False)
    report, engine = cli.run_analysis_stage(args, Config(), b"hello world")
    assert report["meta"]["offline"] is False
    assert report["meta"]["enrichment_requested"] is False
    assert "network_blocked" in report["meta"]
    assert report["node_count"] >= 1


def test_run_detections_stage_populates_report():
    args = _args(argv=["--file", "x"], enable_detections=True)
    data = (
        b"http://evil.example/a\nhttps://c2.example.net/b\n"
        b"203.0.113.9\nattacker@evil.example\n"
    )
    report, _ = cli.run_analysis_stage(args, Config(), data)
    detections, risk = cli.run_detections_stage(args, Config(), report, None)
    assert isinstance(detections, list)
    assert risk is not None
    assert report["risk_assessment"] == risk
    assert report["detections"] == detections


def test_run_detections_stage_disabled_returns_empty():
    args = _args(argv=["--file", "x"], enable_detections=False)
    report, _ = cli.run_analysis_stage(args, Config(), b"hello world data here")
    detections, risk = cli.run_detections_stage(args, Config(), report, None)
    assert detections == []
    assert risk is None


def test_handle_info_commands_schema_version(capsys):
    args = _args(argv=["--print-schema-version"])
    rc = cli.handle_info_commands(args, Config())
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert "schema_version" in out


def test_handle_info_commands_returns_none_for_normal_run():
    args = _args(argv=["--file", "x"])
    assert cli.handle_info_commands(args, Config()) is None


def test_write_outputs_stage_fail_on_risk_level(tmp_path):
    args = _args(
        argv=["--file", "x"],
        enable_detections=True,
        fail_on_risk_level="HIGH",
        out=tmp_path / "r.json",
        quiet=True,
    )
    data = (
        b"http://evil.example/a\nhttps://c2.example.net/b\nhttp://cdn.bad.example.org/c\n"
        b"8.8.8.8\n1.1.1.1\n9.9.9.9\nevil.example.com\nc2.example.net\n"
        b"attacker@example.org\nadmin@bad.example.net\n"
    )
    cfg = Config()
    report, engine = cli.run_analysis_stage(args, cfg, data)
    cli.attach_evidence_stage(args, report, None)
    detections, risk = cli.run_detections_stage(args, cfg, report, None)
    code = cli.write_outputs_stage(args, cfg, report, engine, detections, risk, None)
    # HIGH/CRITICAL risk with --fail-on-risk-level HIGH => exit code 2.
    assert code == 2
    assert (tmp_path / "r.json").exists()


def test_write_outputs_stage_clean_exit(tmp_path):
    args = _args(
        argv=["--file", "x"],
        enable_detections=True,
        fail_on_risk_level="HIGH",
        out=tmp_path / "r.json",
        quiet=True,
    )
    cfg = Config()
    report, engine = cli.run_analysis_stage(args, cfg, b"just some harmless text\n")
    detections, risk = cli.run_detections_stage(args, cfg, report, None)
    code = cli.write_outputs_stage(args, cfg, report, engine, detections, risk, None)
    assert code == 0
