from pathlib import Path

from titan_decoder.workbench_ui.models import AnalysisSnapshot
from titan_decoder.workbench_ui.presenters import correlation_text, timeline_text


def sample_report():
    return {
        "evidence": {
            "events": [
                {
                    "timestamp": "2026-01-01T00:00:00Z",
                    "event_type": "dns",
                    "summary": "query",
                }
            ]
        },
        "correlation": {
            "relationships": [
                {
                    "left_analysis_id": "a",
                    "right_analysis_id": "b",
                    "score": 0.8,
                    "confidence": "high",
                }
            ]
        },
        "campaigns": {
            "campaigns": [{"confidence": "high", "member_analysis_ids": ["a", "b"]}]
        },
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
    from textual.widgets import Input

    from titan_decoder.workbench_ui.app import ResultsPanel, TitanWorkbenchApp

    async def exercise():
        app = TitanWorkbenchApp()
        async with app.run_test():
            await app._show_center_overlay("first")
            await app._show_center_overlay("second")
            await app.refresh_results()
            await app.refresh_results()
            await app.refresh_decoder_details()
            assert len(app.query("#dynamic-view")) == 1

            app.query_one("#evidence-input", Input).value = "A" * 300
            data, source_name = app._read_input()
            assert data == b"A" * 300
            assert source_name == "pasted input"

            await app.action_show_reports()
            await app.action_show_dashboard()
            assert isinstance(app.query_one("#dynamic-view"), ResultsPanel)

    asyncio.run(exercise())


def test_ci_installs_the_required_textual_extra():
    workflow = Path(".github/workflows/tests.yml").read_text(encoding="utf-8")
    assert "-e '.[workbench-ui]'" in workflow


def test_analysis_worker_refreshes_results_without_duplicate_ids(monkeypatch):
    import asyncio
    import pytest

    pytest.importorskip("textual")
    from textual.widgets import Input

    from titan_decoder.workbench_ui.app import ResultsPanel, TitanWorkbenchApp

    async def exercise():
        app = TitanWorkbenchApp()

        def fake_analyze(data, source_name):
            return AnalysisSnapshot(
                source_name=source_name,
                source_size=len(data),
                report={"nodes": [{"depth": 0}]},
            )

        monkeypatch.setattr(app.services, "analyze", fake_analyze)
        async with app.run_test():
            app.query_one("#evidence-input", Input).value = "A" * 300
            worker = app.start_analysis()
            await app.workers.wait_for_complete([worker])
            assert isinstance(app.query_one("#dynamic-view"), ResultsPanel)
            assert app.snapshot.source_size == 300

    asyncio.run(exercise())


def test_analysis_reveals_results_on_short_terminals(monkeypatch):
    """Regression: on short terminals the results panel rendered below the fold,
    so a finished analysis looked like it produced nothing."""
    import asyncio
    import pytest

    pytest.importorskip("textual")
    from textual.widgets import Input, Static

    from titan_decoder.workbench_ui.app import TitanWorkbenchApp

    async def exercise():
        app = TitanWorkbenchApp()

        def fake_analyze(data, source_name):
            return AnalysisSnapshot(
                source_name=source_name,
                source_size=len(data),
                report={"nodes": [{"depth": 0}]},
            )

        monkeypatch.setattr(app.services, "analyze", fake_analyze)
        async with app.run_test(size=(120, 30)) as pilot:
            app.query_one("#evidence-input", Input).value = "A" * 300
            column = app.query_one("#center-column")
            assert column.scroll_offset.y == 0
            worker = app.start_analysis()
            await app.workers.wait_for_complete([worker])
            await pilot.pause()
            assert column.scroll_offset.y > 0, (
                "results panel was not scrolled into view"
            )
            # the busy indicator must be back to Ready once the worker finishes
            footer = app.query_one("#footer-state", Static)
            assert "Ready" in str(footer.renderable)

    asyncio.run(exercise())


def test_dense_scrollable_shell_and_quick_start_actions():
    import asyncio
    import pytest

    pytest.importorskip("textual")
    from textual.containers import HorizontalScroll, VerticalScroll
    from textual.widgets import Header, Footer, Input, OptionList

    from titan_decoder.workbench_ui.app import TitanWorkbenchApp
    from titan_decoder.workbench_ui.widgets import (
        WorkbenchHeader,
        WorkbenchStatusBar,
        NavigationPanel,
        StatusCards,
    )

    async def exercise():
        app = TitanWorkbenchApp()
        async with app.run_test(size=(120, 40)) as pilot:
            assert len(app.query(WorkbenchHeader)) == 1
            assert len(app.query(WorkbenchStatusBar)) == 1
            assert len(app.query(Header)) == 0
            assert len(app.query(Footer)) == 0
            assert isinstance(app.query_one("#center-column"), VerticalScroll)
            assert isinstance(app.query_one("#right-column"), VerticalScroll)
            assert isinstance(app.query_one(NavigationPanel), VerticalScroll)
            assert isinstance(app.query_one(StatusCards), HorizontalScroll)
            assert app.screen.has_class("compact-layout")

            quick_start = app.query_one("#quick-start-list", OptionList)
            quick_start.focus()
            quick_start.highlighted = 1
            await pilot.press("enter")
            assert app.input_mode == "hex"
            assert app.query_one("#evidence-input", Input).has_focus

            await app.action_show_help()
            assert len(app.query("#dynamic-view")) == 1

            app.services.update_state(profile="full", offline=False, aggressive=True)
            app.refresh_shell_status()
            assert app.query_one(WorkbenchHeader).state == app.services.state
            assert app.query_one(WorkbenchStatusBar).state == app.services.state
            assert app.query_one(StatusCards).state == app.services.state

    asyncio.run(exercise())


def test_short_integrated_ui_command_is_packaged():
    pyproject = Path("pyproject.toml").read_text(encoding="utf-8")
    assert 'titan-ui = "titan_decoder.workbench_ui.app:main"' in pyproject
