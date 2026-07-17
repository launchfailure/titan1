from titan_decoder.workbench_ui.models import AnalysisSnapshot
from titan_decoder.workbench_ui.presenters import (
    correlation_text,
    decode_tree_text,
    decoded_text,
    hex_preview,
    iocs_text,
    strings_text,
    summary_text,
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
