from titan_decoder.core.detection_rules import CorrelationRulesEngine, DetectionRule


def test_load_starter_rules():
    engine = CorrelationRulesEngine()
    assert len(engine.rules) >= 7
    rule_ids = [r.rule_id for r in engine.rules]
    assert "TITAN-001" in rule_ids
    assert "TITAN-007" in rule_ids
    assert "TITAN-008" in rule_ids
    assert "TITAN-009" in rule_ids
    assert "TITAN-010" in rule_ids
    assert "TITAN-011" in rule_ids
    assert "TITAN-012" in rule_ids


def test_deep_base64_detection():
    report = {
        "nodes": [
            {"depth": 0, "decoder_used": "Base64"},
            {"depth": 1, "decoder_used": "Base64"},
            {"depth": 2, "decoder_used": "Base64"},
            {"depth": 3, "decoder_used": "Base64"},
        ]
    }
    iocs = {}

    engine = CorrelationRulesEngine()
    detections = engine.evaluate_all(report, iocs)

    assert any(d["rule_id"] == "TITAN-001" for d in detections)


def test_office_macro_network_detection():
    report = {
        "nodes": [
            {"method": "ANALYZE_OLE", "content_preview": "VBA content"},
        ]
    }
    iocs = {
        "urls": ["http://malicious.com"],
        "ipv4_public": ["1.2.3.4"],
    }

    engine = CorrelationRulesEngine()
    detections = engine.evaluate_all(report, iocs)

    assert any(d["rule_id"] == "TITAN-002" for d in detections)


def _lolbin_fires(preview: str) -> bool:
    report = {"nodes": [{"depth": 0, "content_preview": preview}]}
    engine = CorrelationRulesEngine()
    dets = engine.evaluate_all(report, {})
    return any(d["rule_id"] == "TITAN-003" for d in dets)


def test_lolbin_fires_with_abuse_context():
    # A LOLBin name together with a strong abuse token should fire.
    assert _lolbin_fires("powershell -nop -w hidden -enc SQBFAFgA")
    assert _lolbin_fires("regsvr32 /s /i:file.sct scrobj.dll")
    assert _lolbin_fires("cmd.exe /c whoami & echo done")


def test_lolbin_does_not_fire_on_bare_mention():
    # Benign documentation that merely names a LOLBin (no abuse context) must
    # NOT fire — this was the false positive the rule hardening addresses.
    assert not _lolbin_fires(
        "On Windows, open PowerShell or cmd.exe and run the installer."
    )
    assert not _lolbin_fires("This script uses wscript to display a dialog.")
    assert not _lolbin_fires("See the PowerShell docs for details.")


def test_rtf_active_content_requires_a_strong_delivery_chain():
    engine = CorrelationRulesEngine()
    active_report = {
        "nodes": [
            {"method": "ANALYZE_RTF", "artifact_name": ""},
            {"artifact_name": "rtf_object_001.exe", "content_preview": "MZ"},
            {
                "artifact_name": "rtf_summary.json",
                "content_preview": '{"active_content":{"embedded_executable":true}}',
            },
        ]
    }
    detections = engine.evaluate_all(active_report, {"urls": ["https://c2.example/a"]})
    assert any(item["rule_id"] == "TITAN-009" for item in detections)

    # A normal hyperlink without an object, and a passive non-executable
    # attachment without network/update behavior, are benign near-misses.
    hyperlink_only = {"nodes": [{"method": "ANALYZE_RTF"}]}
    assert not any(
        item["rule_id"] == "TITAN-009"
        for item in engine.evaluate_all(
            hyperlink_only, {"urls": ["https://example.com"]}
        )
    )
    passive_object = {
        "nodes": [
            {"method": "ANALYZE_RTF"},
            {"artifact_name": "rtf_object_001.bin"},
            {"artifact_name": "rtf_summary.json", "content_preview": "{}"},
        ]
    }
    assert not any(
        item["rule_id"] == "TITAN-009"
        for item in engine.evaluate_all(passive_object, {})
    )


def test_xlm_detection_requires_a_macro_sheet_artifact_and_high_risk_function():
    engine = CorrelationRulesEngine()
    report = {
        "nodes": [
            {
                "artifact_name": "office_xlm_macros.txt",
                "content_preview": '[xl/macrosheets/sheet1.xml] =EXEC("calc.exe")',
            }
        ]
    }
    assert any(
        item["rule_id"] == "TITAN-010" for item in engine.evaluate_all(report, {})
    )
    ordinary = {
        "nodes": [
            {
                "artifact_name": "office_xlm_macros.txt",
                "content_preview": "[xl/macrosheets/sheet1.xml] =SUM(1,2)",
            }
        ]
    }
    assert not any(
        item["rule_id"] == "TITAN-010" for item in engine.evaluate_all(ordinary, {})
    )


def test_msi_detection_requires_package_executable_and_network_indicator():
    engine = CorrelationRulesEngine()
    report = {
        "nodes": [
            {"method": "ANALYZE_MSI", "artifact_name": ""},
            {"artifact_name": "msi_payload_001.exe", "content_preview": "MZ"},
        ]
    }
    assert any(
        item["rule_id"] == "TITAN-011"
        for item in engine.evaluate_all(report, {"domains": ["c2.example"]})
    )
    assert not any(
        item["rule_id"] == "TITAN-011" for item in engine.evaluate_all(report, {})
    )
    url_only = {"nodes": [{"method": "ANALYZE_MSI"}]}
    assert not any(
        item["rule_id"] == "TITAN-011"
        for item in engine.evaluate_all(url_only, {"urls": ["https://example.com"]})
    )


def test_onenote_detection_requires_section_executable_and_network_indicator():
    engine = CorrelationRulesEngine()
    report = {
        "nodes": [
            {"method": "ANALYZE_OneNote", "artifact_name": ""},
            {"artifact_name": "onenote_file_001.exe", "content_preview": "MZ"},
        ]
    }
    assert any(
        item["rule_id"] == "TITAN-012"
        for item in engine.evaluate_all(report, {"urls": ["https://c2.example/a"]})
    )
    assert not any(
        item["rule_id"] == "TITAN-012" for item in engine.evaluate_all(report, {})
    )
    passive = {
        "nodes": [
            {"method": "ANALYZE_OneNote"},
            {"artifact_name": "onenote_file_001.pdf"},
        ]
    }
    assert not any(
        item["rule_id"] == "TITAN-012"
        for item in engine.evaluate_all(passive, {"domains": ["example.com"]})
    )


def test_custom_rule_addition():
    engine = CorrelationRulesEngine()
    initial_count = len(engine.rules)

    custom_rule = DetectionRule(
        rule_id="CUSTOM-001",
        name="Test Rule",
        description="A test rule",
        severity="medium",
        detect_fn=lambda report, iocs: True,
    )

    engine.add_custom_rule(custom_rule)
    assert len(engine.rules) == initial_count + 1
