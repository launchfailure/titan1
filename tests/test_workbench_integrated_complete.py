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


def test_ci_installs_every_required_optional_test_dependency():
    workflow = Path(".github/workflows/tests.yml").read_text(encoding="utf-8")
    assert "-e '.[workbench-ui,desktop-ui,formats]'" in workflow
    assert "'yara-python>=4.5.4'" in workflow
    assert "pytest -q --fail-on-skips" in workflow


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
            # The reveal is scheduled via call_after_refresh, which under
            # Textual 8's frame scheduling may take more than one pause to
            # land; wait for the scroll instead of sampling a single frame.
            for _ in range(20):
                await pilot.pause()
                if column.scroll_offset.y > 0:
                    break
            assert column.scroll_offset.y > 0, (
                "results panel was not scrolled into view"
            )
            # the busy indicator must be back to Ready once the worker finishes
            # str(render()) works on both old Textual (returns .renderable)
            # and Textual >=8, where Static.renderable was removed.
            footer = app.query_one("#footer-state", Static)
            assert "Ready" in str(footer.render())

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


def test_single_titan_command_is_packaged():
    text = Path("pyproject.toml").read_text(encoding="utf-8")
    scripts = text.split("[project.scripts]", 1)[1].split(
        "[project.optional-dependencies]", 1
    )[0]
    registered = [
        line.strip()
        for line in scripts.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    assert registered == ['titan = "titan_decoder.launcher:main"']


def test_terminal_drop_path_normalization():
    import pytest

    pytest.importorskip("textual")
    from titan_decoder.workbench_ui.app import TitanWorkbenchApp

    assert (
        TitanWorkbenchApp._normalize_input_path(
            r'"C:\Users\Analyst\Evidence Files\sample.bin"', posix=True
        )
        == "/mnt/c/Users/Analyst/Evidence Files/sample.bin"
    )
    assert (
        TitanWorkbenchApp._normalize_input_path(
            "file:///C:/Users/Analyst/sample.bin", posix=True
        )
        == "/mnt/c/Users/Analyst/sample.bin"
    )
    assert (
        TitanWorkbenchApp._normalize_input_path(
            "'/home/james/Evidence Files/sample.bin'", posix=True
        )
        == "/home/james/Evidence Files/sample.bin"
    )


def test_terminal_drop_loads_path_and_starts_analysis(tmp_path, monkeypatch):
    import asyncio
    import pytest

    pytest.importorskip("textual")
    from textual.events import Paste
    from textual.widgets import Input, OptionList

    from titan_decoder.workbench_ui.app import TitanWorkbenchApp

    sample = tmp_path / "sample evidence.bin"
    sample.write_bytes(b"evidence")
    started = []
    monkeypatch.setattr(
        TitanWorkbenchApp,
        "start_analysis",
        lambda self: started.append(self.query_one("#evidence-input", Input).value),
    )

    async def exercise():
        app = TitanWorkbenchApp()
        async with app.run_test() as pilot:
            field = app.query_one("#evidence-input", Input)
            field.focus()
            await pilot.pause()
            app.post_message(Paste(f'"{sample}"'))
            await pilot.pause()
            assert field.value == str(sample)
            assert field.has_focus
            assert started == [str(sample)]

            # Paste events bubble to the app when another control has focus,
            # so dropping on the visual workbench still loads the evidence.
            quick_start = app.query_one("#quick-start-list", OptionList)
            quick_start.focus()
            await pilot.pause()
            app.post_message(Paste(str(sample)))
            # Under a heavily loaded full-suite run, Textual can need one
            # extra message-loop turn to deliver a paste posted directly to
            # the app after focus changes.
            for _ in range(3):
                await pilot.pause()
                if len(started) == 2:
                    break
            assert started == [str(sample), str(sample)]

    asyncio.run(exercise())
