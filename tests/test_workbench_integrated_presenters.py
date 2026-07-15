from titan_decoder.workbench_ui.models import AnalysisSnapshot
from titan_decoder.workbench_ui.presenters import hex_preview, summary_text


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
