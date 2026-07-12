from titan_decoder.core.explain import generate_explanation


def test_explanation_contains_summary_and_artifacts():
    report = {
        "intelligence": {
            "intelligence_score": 72,
            "classification": "HIGH_RISK_PAYLOAD",
            "confidence": 0.72,
            "signals": [
                {
                    "code": "execution_context",
                    "points": 16,
                    "summary": "Command or script execution context was found",
                }
            ],
            "top_artifacts": [
                {
                    "node_id": 3,
                    "artifact_name": "stage.ps1",
                    "score": 80,
                    "reasons": ["execution context", "network indicator"],
                }
            ],
            "recommendation": "High-priority manual review",
        }
    }

    output = generate_explanation(report)

    assert "HIGH_RISK_PAYLOAD" in output
    assert "72/100" in output
    assert "stage.ps1" in output
    assert "High-priority manual review" in output
