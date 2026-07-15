import json
from pathlib import Path

from titan_decoder.workbench_ui.models import AnalysisSnapshot
from titan_decoder.workbench_ui.presenters import correlation_text, timeline_text


def sample_report():
    return {
        "evidence": {"events": [{"timestamp": "2026-01-01T00:00:00Z", "event_type": "dns", "summary": "query"}]},
        "correlation": {"relationships": [{"left_analysis_id": "a", "right_analysis_id": "b", "score": .8, "confidence": "high"}]},
        "campaigns": {"campaigns": [{"confidence": "high", "member_analysis_ids": ["a", "b"]}]},
    }


def test_real_timeline_and_correlation_presenters():
    snapshot = AnalysisSnapshot(report=sample_report())
    assert "dns" in timeline_text(snapshot)
    assert "a ↔ b" in correlation_text(snapshot)
    assert "campaign" in correlation_text(snapshot)


def test_package_import_does_not_require_textual():
    import titan_decoder.workbench_ui as package
    assert "TitanWorkbenchApp" in package.__all__


def test_dynamic_view_replacement_waits_for_removal():
    """Regression: sequential Textual view swaps must not duplicate the widget id."""
    import asyncio
    import pytest

    textual = pytest.importorskip("textual")
    del textual
    from titan_decoder.workbench_ui.app import TitanWorkbenchApp

    async def exercise():
        app = TitanWorkbenchApp()
        async with app.run_test():
            await app._show_center_overlay("first")
            await app._show_center_overlay("second")
            assert len(app.query("#dynamic-view")) == 1

    asyncio.run(exercise())
