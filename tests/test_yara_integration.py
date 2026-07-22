"""Tests for bounded, deterministic YARA scanning across the artifact graph."""

import base64
import json

import pytest

from titan_decoder import cli
from titan_decoder.config import Config
from titan_decoder.core.engine import TitanEngine
from titan_decoder.core.yara_scanner import (
    YaraScanner,
    yara_matches_to_detections,
    yara_available,
)

yara = pytest.importorskip("yara")

MARKER_RULE = """
rule Titan_Test_Marker {
  meta:
    description = "Titan integration test marker"
    severity = "high"
    attack_id = "T1105"
  strings:
    $a = "titan-yara-marker"
  condition:
    $a
}
"""


def _write_rules(tmp_path, name="marker.yar", body=MARKER_RULE):
    path = tmp_path / name
    path.write_text(body, encoding="utf-8")
    return path


def _args(argv):
    return cli.build_parser().parse_args(argv)


def test_yara_matches_decoded_content_invisible_in_raw_input(tmp_path):
    rules = _write_rules(tmp_path)
    payload = b"titan-yara-marker http://yara.example/stage"
    sample = base64.b64encode(payload)
    engine = TitanEngine()
    engine.run_analysis(sample)
    payloads = engine.artifact_payloads()

    scanner = YaraScanner({"enable_yara": True, "yara_rules_path": str(rules)})
    result = scanner.scan(payloads)
    assert result["state"] == "completed"
    matched_nodes = {match["node_id"] for match in result["matches"]}
    # The marker only exists after base64 decoding, so the match must be on
    # a decoded node — scanning the raw input alone finds nothing.
    assert matched_nodes and all(node_id > 0 for node_id in matched_nodes)
    root_only = YaraScanner({"enable_yara": True, "yara_rules_path": str(rules)}).scan(
        payloads[:1]
    )
    assert root_only["matches"] == []


def test_yara_scan_is_deterministic_and_namespaced_by_file(tmp_path):
    directory = tmp_path / "rules"
    directory.mkdir()
    _write_rules(directory, "b_second.yar", MARKER_RULE.replace("Marker", "Second"))
    _write_rules(directory, "a_first.yar")
    scanner_config = {"enable_yara": True, "yara_rules_dirs": [str(directory)]}
    payloads = [(0, b"prefix titan-yara-marker suffix")]

    first = YaraScanner(scanner_config).scan(payloads)
    second = YaraScanner(scanner_config).scan(payloads)
    assert first == second
    assert first["state"] == "completed"
    assert [match["namespace"] for match in first["matches"]] == [
        "a_first",
        "b_second",
    ]
    match = first["matches"][0]
    assert match["rule"] == "Titan_Test_Marker"
    assert match["severity"] == "high"
    assert match["meta"]["attack_id"] == "T1105"
    assert match["strings"][0]["data"] == "titan-yara-marker"


def test_yara_fails_closed_when_rules_are_missing_or_disabled(tmp_path):
    assert yara_available() is True
    missing = YaraScanner(
        {"enable_yara": True, "yara_rules_path": str(tmp_path / "missing.yar")}
    ).scan([(0, b"data")])
    assert missing["state"] == "unavailable"
    assert "not found" in missing["reason"]

    disabled = YaraScanner({}).scan([(0, b"data")])
    assert disabled["state"] == "not_configured"

    broken = _write_rules(tmp_path, "broken.yar", "rule Broken { condition: ")
    invalid = YaraScanner({"enable_yara": True, "yara_rules_path": str(broken)}).scan(
        [(0, b"data")]
    )
    assert invalid["state"] == "unavailable"
    assert "compilation failed" in invalid["reason"]


def test_yara_match_limit_is_enforced(tmp_path):
    rules = _write_rules(tmp_path)
    payloads = [(0, b"titan-yara-marker"), (1, b"titan-yara-marker again")]
    result = YaraScanner(
        {
            "enable_yara": True,
            "yara_rules_path": str(rules),
            "yara_max_matches": 1,
        }
    ).scan(payloads)
    assert len(result["matches"]) == 1
    assert result["match_limit_reached"] is True


def test_yara_matches_convert_to_grouped_detections(tmp_path):
    rules = _write_rules(tmp_path)
    payloads = [(0, b"titan-yara-marker"), (3, b"titan-yara-marker again")]
    result = YaraScanner({"enable_yara": True, "yara_rules_path": str(rules)}).scan(
        payloads
    )
    detections = yara_matches_to_detections(result)
    assert len(detections) == 1
    detection = detections[0]
    assert detection["rule_id"] == "YARA:marker:Titan_Test_Marker"
    assert detection["severity"] == "high"
    assert detection["node_ids"] == [0, 3]
    assert detection["attack_ids"] == ["T1105"]
    assert detection["source"] == {
        "type": "yara",
        "namespace": "marker",
        "rule": "Titan_Test_Marker",
    }
    assert yara_matches_to_detections({"state": "unavailable", "matches": []}) == []


def test_cli_detection_stage_runs_yara_and_feeds_risk(tmp_path):
    rules = _write_rules(tmp_path)
    sample = base64.b64encode(b"titan-yara-marker http://yara.example/stage")
    args = _args(["--file", "x", "--enable-detections", "--yara-rules", str(rules)])
    config = Config(tmp_path / "missing-config.json")
    engine = TitanEngine(config)
    report = engine.run_analysis(sample)

    detections, risk = cli.run_detections_stage(args, config, report, None, engine)

    assert report["yara"]["state"] == "completed"
    yara_detections = [
        item for item in detections if item["source"].get("type") == "yara"
    ]
    assert [item["rule_id"] for item in yara_detections] == [
        "YARA:marker:Titan_Test_Marker"
    ]
    assert risk["breakdown"]["yara"] > 0
    assert any(reason.startswith("YARA:") for reason in risk["top_reasons"])
    # The persisted report stays JSON-serializable with the new section.
    json.dumps(report)


def test_cli_offline_mode_keeps_yara_enabled(tmp_path):
    rules = _write_rules(tmp_path)
    args = _args(
        [
            "--file",
            "x",
            "--offline",
            "--enable-detections",
            "--yara-rules",
            str(rules),
        ]
    )
    config = Config(tmp_path / "missing-config.json")
    cli.apply_runtime_config(args, config)
    engine = TitanEngine(config)
    report = engine.run_analysis(base64.b64encode(b"titan-yara-marker"))
    cli.run_detections_stage(args, config, report, None, engine)
    assert report["yara"]["state"] == "completed"
    assert report["yara"]["matches"]
