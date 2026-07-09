from titan_decoder.core.risk_scoring import RiskScoringEngine


def test_compute_risk_score_clean():
    report = {"nodes": [{"id": 0, "depth": 0, "entropy": 3.0}]}
    iocs = {}
    detections = []

    engine = RiskScoringEngine()
    result = engine.compute_risk_score(report, iocs, detections)

    assert result["risk_level"] == "CLEAN"
    assert result["risk_score"] == 0


def test_compute_risk_score_with_detections():
    report = {"nodes": [{"id": 0, "depth": 4, "entropy": 7.8}]}
    iocs = {
        "ipv4_public": ["1.2.3.4", "5.6.7.8"],
        "urls": ["http://malicious.com"],
        "domains": ["evil.com"],
    }
    detections = [
        {"rule_id": "TITAN-001", "name": "Test", "severity": "critical"},
        {"rule_id": "TITAN-002", "name": "Test", "severity": "high"},
    ]

    engine = RiskScoringEngine()
    result = engine.compute_risk_score(report, iocs, detections)

    assert result["risk_score"] > 50
    assert result["risk_level"] in ["HIGH", "CRITICAL"]
    assert len(result["top_reasons"]) > 0


def test_severity_floor_lifts_lone_medium_detection():
    # Regression: a single medium-severity detection contributes only 15 points
    # (< the MEDIUM threshold of 25), so before the floor a fired rule like
    # "LOLBin Script Execution" read LOW. The severity floor must lift it to
    # MEDIUM so a genuine detection is not under-prioritized.
    report = {"nodes": [{"id": 0, "depth": 1, "entropy": 4.0}]}
    iocs = {}
    detections = [{"rule_id": "TITAN-003", "name": "LOLBin", "severity": "medium"}]

    result = RiskScoringEngine().compute_risk_score(report, iocs, detections)
    assert result["risk_level"] == "MEDIUM"
    assert result["risk_score"] >= 25


def test_severity_floor_maps_high_and_critical():
    eng = RiskScoringEngine()
    report = {"nodes": [{"id": 0, "depth": 0, "entropy": 3.0}]}
    high = eng.compute_risk_score(
        report, {}, [{"rule_id": "X", "name": "h", "severity": "high"}]
    )
    crit = eng.compute_risk_score(
        report, {}, [{"rule_id": "Y", "name": "c", "severity": "critical"}]
    )
    assert high["risk_level"] in ("HIGH", "CRITICAL") and high["risk_score"] >= 50
    assert crit["risk_level"] == "CRITICAL" and crit["risk_score"] >= 75


def test_severity_floor_does_not_affect_clean_runs():
    # No detections -> floor never applies; benign inputs stay CLEAN/LOW.
    report = {"nodes": [{"id": 0, "depth": 0, "entropy": 3.0}]}
    result = RiskScoringEngine().compute_risk_score(report, {}, [])
    assert result["risk_level"] == "CLEAN"
    assert result["risk_score"] == 0


def test_get_top_risky_nodes():
    report = {
        "nodes": [
            {
                "id": 0,
                "depth": 0,
                "entropy": 3.0,
                "decode_score": 0.1,
                "content_preview": "hello",
                "method": "ANALYZE",
            },
            {
                "id": 1,
                "depth": 2,
                "entropy": 8.5,
                "decode_score": 0.9,
                "content_preview": "MZ binary",
                "method": "Base64",
            },
            {
                "id": 2,
                "depth": 1,
                "entropy": 5.0,
                "decode_score": 0.3,
                "content_preview": "data",
                "method": "Gzip",
            },
        ]
    }

    engine = RiskScoringEngine()
    risky_nodes = engine.get_top_risky_nodes(report, limit=3)

    assert len(risky_nodes) == 3
    # Node with high entropy and MZ should be most risky
    assert risky_nodes[0]["node_id"] == 1
