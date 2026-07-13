from titan_decoder.core.case_report import build_case_report, to_html, to_markdown


def _intelligence():
    return {
        "version": "1.0",
        "intelligence_score": 62,
        "classification": "HIGH_RISK_PAYLOAD",
        "confidence": 0.62,
        "signals": [
            {
                "code": "detection_rules",
                "points": 30,
                "summary": "One high-severity detection triggered",
                "evidence": ["Fixture high"],
            },
            {
                "code": "execution_context",
                "points": 16,
                "summary": "Command or script execution context was found",
                "evidence": [7],
            },
        ],
        "top_artifacts": [
            {
                "node_id": 7,
                "artifact_name": "decoded-script",
                "method": "Base64",
                "score": 65,
                "reasons": ["execution context", "deep decode depth 4"],
            }
        ],
        "recommendation": "High-priority manual review",
    }


def test_case_report_copies_intelligence_without_recomputation():
    intelligence = _intelligence()
    report = {
        "meta": {"analysis_id": "fixture"},
        "node_count": 8,
        "intelligence": intelligence,
    }

    case = build_case_report(report, None, {"urls": ["https://example.test/a"]})

    assert case["intelligence"] == intelligence
    assert case["intelligence"] is not intelligence
    assert case["recommendations"][0] == intelligence["recommendation"]


def test_markdown_contains_intelligence_summary_signals_and_artifacts():
    case = build_case_report(
        {"meta": {}, "node_count": 8, "intelligence": _intelligence()},
        None,
        {"urls": ["https://example.test/a"]},
    )

    rendered = to_markdown(case)

    assert "## Intelligence Assessment" in rendered
    assert "**Classification:** HIGH_RISK_PAYLOAD" in rendered
    assert "**Score:** 62/100" in rendered
    assert "**Confidence:** 62%" in rendered
    assert "### Top Signals" in rendered
    assert "**detection_rules** (+30)" in rendered
    assert "### Highest-Priority Artifacts" in rendered
    assert "| 1 | 7 | decoded-script | Base64 | 65 |" in rendered
    assert "High-priority manual review" in rendered


def test_html_contains_intelligence_summary_signals_and_artifacts():
    case = build_case_report(
        {"meta": {}, "node_count": 8, "intelligence": _intelligence()},
        None,
        {"urls": ["https://example.test/a"]},
    )

    rendered = to_html(case)

    assert "<section id='intelligence'>" in rendered
    assert "HIGH_RISK_PAYLOAD" in rendered
    assert "62/100" in rendered
    assert "62%" in rendered
    assert "detection_rules" in rendered
    assert "decoded-script" in rendered
    assert "High-priority manual review" in rendered


def test_report_renderers_remain_backward_compatible_without_intelligence():
    case = build_case_report(
        {"meta": {"analysis_id": "legacy"}, "node_count": 0},
        None,
        {},
    )

    markdown = to_markdown(case)
    html = to_html(case)

    assert "## Intelligence Assessment" not in markdown
    assert "id='intelligence'" not in html
    assert "## Indicators" in markdown
    assert "<h2>Indicators</h2>" in html


def test_html_escapes_untrusted_intelligence_content():
    intelligence = _intelligence()
    intelligence["signals"][0]["summary"] = "<script>alert('x')</script>"
    intelligence["top_artifacts"][0]["artifact_name"] = "<img src=x onerror=alert(1)>"

    case = build_case_report(
        {"meta": {}, "node_count": 1, "intelligence": intelligence},
        None,
        {},
    )
    rendered = to_html(case)

    assert "<script>" not in rendered
    assert "<img src=x" not in rendered
    assert "&lt;script&gt;" in rendered
    assert "&lt;img src=x onerror=alert(1)&gt;" in rendered
