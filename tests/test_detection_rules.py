from titan_decoder.core.detection_rules import CorrelationRulesEngine, DetectionRule


def test_load_starter_rules():
    engine = CorrelationRulesEngine()
    assert len(engine.rules) >= 7
    rule_ids = [r.rule_id for r in engine.rules]
    assert "TITAN-001" in rule_ids
    assert "TITAN-007" in rule_ids
    assert "TITAN-008" in rule_ids


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


def test_lolbin_does_not_fire_on_bare_mention():
    # Benign documentation that merely names a LOLBin (no abuse context) must
    # NOT fire — this was the false positive the rule hardening addresses.
    assert not _lolbin_fires(
        "On Windows, open PowerShell or cmd.exe and run the installer."
    )
    assert not _lolbin_fires("This script uses wscript to display a dialog.")
    assert not _lolbin_fires("See the PowerShell docs for details.")


def test_lolbin_does_not_fire_on_routine_admin_flags():
    # These flags are common in legitimate automation. They need stronger abuse
    # evidence before Titan promotes them to a detection.
    assert not _lolbin_fires(
        r"powershell.exe -NoProfile -File C:\Admin\Rotate-Logs.ps1"
    )
    assert not _lolbin_fires("cmd.exe /c echo nightly backup complete")
    assert not _lolbin_fires("cscript //nologo inventory.vbs")


def test_opaque_payload_requires_executable_or_packer_context():
    engine = CorrelationRulesEngine()

    generic_ciphertext = {
        "nodes": [
            {
                "entropy": 7.95,
                "content_preview": "random encrypted backup bytes",
                "decode_score": 0.0,
            }
        ]
    }
    generic_ids = {
        item["rule_id"] for item in engine.evaluate_all(generic_ciphertext, {})
    }
    assert "TITAN-004" not in generic_ids

    opaque_executable = {
        "nodes": [
            {
                "entropy": 7.95,
                "content_preview": "MZ" + "X" * 100,
                "decode_score": 0.0,
            }
        ]
    }
    executable_ids = {
        item["rule_id"] for item in engine.evaluate_all(opaque_executable, {})
    }
    assert "TITAN-004" in executable_ids


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
