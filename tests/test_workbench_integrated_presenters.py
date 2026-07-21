from titan_decoder.workbench_ui.models import AnalysisSnapshot
from titan_decoder.workbench_ui.presenters import (
    correlation_text,
    decode_tree_text,
    decoded_text,
    findings_text,
    hex_preview,
    iocs_text,
    strings_text,
    summary_text,
    timeline_text,
)


def test_hex_preview_contains_offset():
    assert "00000000" in hex_preview(b"ABC")


def test_summary_uses_real_snapshot_counts():
    snapshot = AnalysisSnapshot(
        source_name="sample",
        source_size=10,
        report={"nodes": [{"depth": 0}], "iocs": {"domains": ["x"]}},
    )
    text = summary_text(snapshot)
    assert "Decode nodes" in text
    assert "IOCs extracted" in text


def test_partial_decode_summary_is_explicit_and_not_a_benign_verdict():
    snapshot = AnalysisSnapshot(
        report={
            "nodes": [
                {
                    "id": 0,
                    "depth": 0,
                    "method": "DECODE_ROT13",
                    "decoder_used": "ROT13",
                    "decode_score": 0.07,
                    "analysis_state": "decoded",
                    "termination_reason": "Applied ROT13 with confidence 0.070.",
                    "content_type": "Text",
                    "content_preview": "encoded",
                },
                {
                    "id": 1,
                    "depth": 1,
                    "method": "ANALYZE",
                    "analysis_state": "terminal",
                    "termination_reason": (
                        "No supported analyzer or decoder accepted the remaining payload."
                    ),
                    "content_type": "Binary",
                    "content_preview": "opaque",
                },
            ],
            "iocs": {},
            "analysis_outcome": {
                "status": "partial_decode",
                "complete": False,
                "summary": (
                    "Applied 1 transformation(s), then stopped with 1 "
                    "unrecognized terminal payload(s)."
                ),
                "opaque_terminal_node_ids": [1],
                "weak_decodes": [{"node_id": 0, "decoder": "ROT13", "score": 0.07}],
            },
        }
    )

    summary = summary_text(snapshot)
    findings = findings_text(snapshot)
    tree = decode_tree_text(snapshot)

    assert "Partial decode" in summary
    assert "Not fully interpreted" in summary
    assert "not a benign verdict" in findings
    assert "LOW CONFIDENCE" in tree
    assert "STOP_UNRECOGNIZED" in tree
    assert "No supported analyzer" in tree


def test_findings_distinguish_no_indicators_from_no_analysis():
    # Before any analysis there is nothing to report.
    assert findings_text(AnalysisSnapshot()) == "No findings loaded."

    # A completed analysis with no indicators must not read like a failure.
    decoded_but_clean = AnalysisSnapshot(
        report={"nodes": [{"depth": 0}, {"depth": 1}], "iocs": {"urls": []}}
    )
    text = findings_text(decoded_but_clean)
    assert "No indicators or detections extracted." in text
    assert "analysis overview" in text

    # Indicators still render as counts.
    with_iocs = AnalysisSnapshot(report={"iocs": {"urls": ["http://x"]}})
    assert "urls" in findings_text(with_iocs)


def test_decode_tree_shows_content_previews():
    snapshot = AnalysisSnapshot(
        report={
            "nodes": [
                {
                    "depth": 0,
                    "method": "DECODE_Base64",
                    "content_type": "Text",
                    "content_preview": "SGVsbG8gVGl0YW4=",
                },
                {
                    "depth": 1,
                    "method": "ANALYZE",
                    "content_type": "Text",
                    "content_preview": "Hello Titan",
                },
            ]
        }
    )
    text = decode_tree_text(snapshot)
    assert "DECODE_Base64" in text
    assert "Hello Titan" in text, "decoded payload preview must be readable"


def test_untrusted_evidence_is_escaped_for_textual_markup():
    malicious = "[/bold][@click=app.quit]quit[/]"
    snapshot = AnalysisSnapshot(
        decoded_output=malicious.encode(),
        report={
            "strings": [malicious],
            "iocs": {"domains": [malicious]},
        },
    )

    for rendered in (
        decoded_text(snapshot),
        strings_text(snapshot),
        iocs_text(snapshot),
    ):
        assert "\\[/bold]" in rendered
        assert "\\[@click=app.quit]" in rendered


def test_malformed_nested_report_values_do_not_crash_presenters():
    snapshot = AnalysisSnapshot(
        report={
            "nodes": [{"depth": "invalid", "method": "[@click=app.quit]"}],
            "iocs": [],
            "detections": "invalid",
            "strings": {"invalid": "shape"},
            "correlation": {"relationships": [{"score": "not-a-number"}, "invalid"]},
            "attribution_hints": "invalid",
            "campaigns": {"campaigns": [{"member_analysis_ids": "invalid"}]},
        }
    )

    assert "\\[@click=app.quit]" in decode_tree_text(snapshot)
    assert "score=0.000" in correlation_text(snapshot)


def test_malformed_timeline_values_do_not_crash_timeline_view():
    # Non-list timeline sources previously raised TypeError from the
    # snapshot property, crashing the workbench Timeline view outright.
    for report in (
        {"timeline": 42},
        {"timeline": True},
        {"evidence": {"events": 99}},
        {"evidence": {"events": {"invalid": "shape"}}, "timeline": "invalid"},
    ):
        text = timeline_text(AnalysisSnapshot(report=report))
        assert text == "No timeline events recorded in the active report."
