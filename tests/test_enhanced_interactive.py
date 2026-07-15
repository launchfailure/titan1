"""Tests for the enhanced interactive console (dashboard ``titan`` UI).

Same approach as test_interactive.py: drive the loop with injected
input/output (no real TTY) and assert observable behavior. The enhanced app
subclasses InteractiveApp, so base behaviors (payload reading, engine
config, aggressive toggle semantics) are covered by the existing suite.
"""

import base64
import io
import json
from pathlib import Path

from titan_decoder.interactive import Style, main as interactive_main
from titan_decoder.ui.console import EnhancedInteractiveApp
from titan_decoder.ui.widgets import box, crop, progress_bar, two_column

EXAMPLES = Path(__file__).resolve().parents[1] / "examples" / "plugins"


def _run(script, app=None):
    it = iter(script)

    def fake_input(prompt=""):
        return next(it)

    out = io.StringIO()
    if app is None:
        app = EnhancedInteractiveApp(input_fn=fake_input, out=out, style=Style(False))
    else:
        app.input_fn = fake_input
        app.out = out
    rc = app.run()
    return rc, out.getvalue()


def test_dashboard_and_menu():
    rc, text = _run(["q"])
    assert rc == 0
    assert "FORENSIC INTELLIGENCE CONSOLE" in text
    assert "QUICK ACTIONS" in text
    assert "SESSION" in text and "SYSTEM" in text
    assert "Plugin manager" in text
    assert "Reports browser" in text
    assert "Session closed." in text


def test_exhausted_input_quits_cleanly():
    # EOF from the input function unwinds via _QuitSignal, not a crash.
    def eof_input(prompt=""):
        raise EOFError

    out = io.StringIO()
    app = EnhancedInteractiveApp(input_fn=eof_input, out=out, style=Style(False))
    assert app.run() == 0
    assert "Session closed." in out.getvalue()


def test_settings_toggle_aggressive_and_reports_dir(tmp_path):
    out = io.StringIO()
    script = iter(["6", "3", "4", str(tmp_path / "reports"), "b", "q"])
    app = EnhancedInteractiveApp(
        input_fn=lambda prompt="": next(script), out=out, style=Style(False)
    )
    assert app.run() == 0
    assert "Aggressive auto-detect is now on" in out.getvalue()
    assert app.aggressive is True
    assert app.reports_dir == tmp_path / "reports"


def test_auto_detect_saves_report(tmp_path):
    payload = base64.b64encode(b"hello interactive world").decode()
    out = io.StringIO()
    script = iter(["1", "1", payload, "", "q"])
    app = EnhancedInteractiveApp(
        input_fn=lambda prompt="": next(script), out=out, style=Style(False)
    )
    app.reports_dir = tmp_path / "reports"
    assert app.run() == 0
    text = out.getvalue()
    assert "ANALYSIS SUMMARY" in text
    assert "Saved report" in text
    saved = json.loads((tmp_path / "reports" / "latest.json").read_text())
    assert saved["node_count"] >= 2


def test_plugin_manager_lists_manifest_plugins():
    out = io.StringIO()
    script = iter(["4", "q"])
    app = EnhancedInteractiveApp(
        input_fn=lambda prompt="": next(script), out=out, style=Style(False)
    )
    app.config.set("plugin_dirs", [str(EXAMPLES)])
    assert app.run() == 0
    text = out.getvalue()
    assert "PLUGIN MANAGER" in text
    assert "example.rot47" in text
    assert "decoder" in text


def test_reports_browser_opens_saved_report(tmp_path):
    report = {
        "meta": {"analysis_id": "browse-test"},
        "node_count": 1,
        "nodes": [{"id": 0, "depth": 0}],
        "iocs": {"urls": ["http://example.test"]},
        "detections": [],
    }
    reports_dir = tmp_path / "reports"
    reports_dir.mkdir()
    (reports_dir / "case.json").write_text(json.dumps(report))

    out = io.StringIO()
    script = iter(["5", "1", "q"])
    app = EnhancedInteractiveApp(
        input_fn=lambda prompt="": next(script), out=out, style=Style(False)
    )
    app.reports_dir = reports_dir
    assert app.run() == 0
    text = out.getvalue()
    assert "REPORTS BROWSER" in text
    assert "case.json" in text
    assert "ANALYSIS SUMMARY" in text
    assert "IOC count         1" in text


def test_reports_browser_handles_missing_dir(tmp_path):
    out = io.StringIO()
    script = iter(["5", "q"])
    app = EnhancedInteractiveApp(
        input_fn=lambda prompt="": next(script), out=out, style=Style(False)
    )
    app.reports_dir = tmp_path / "nonexistent"
    assert app.run() == 0
    assert "No reports directory exists yet." in out.getvalue()


def test_unknown_option_keeps_loop_alive():
    rc, text = _run(["9", "q"])
    assert rc == 0
    assert "Unknown option" in text


def test_decoder_catalog_invalid_selection():
    rc, text = _run(["2", "99", "q"])
    assert rc == 0
    assert "DECODER CATALOG" in text
    assert "Invalid selection." in text


def test_main_entry_point_uses_enhanced_app(monkeypatch):
    calls = {}

    def fake_run(self):
        calls["class"] = type(self).__name__
        return 0

    monkeypatch.setattr(EnhancedInteractiveApp, "run", fake_run)
    assert interactive_main([]) == 0
    assert calls["class"] == "EnhancedInteractiveApp"


def test_widgets_render_and_bound():
    rendered = box("TEST", ["alpha", "beta"], 40)
    lines = rendered.splitlines()
    assert "TEST" in lines[0] and "alpha" in rendered
    assert all(len(line) == 40 for line in lines)

    columns = two_column("L", ["one"], "R", ["a", "b", "c"], 80)
    widths = {len(line) for line in columns.splitlines()}
    assert widths == {80}

    assert progress_bar(1, 2, 10).count("█") == 5
    assert progress_bar(5, 2, 10).count("█") == 10  # clamped
    assert progress_bar(1, 0, 10).count("█") == 0  # zero total

    assert crop("abcdef", 4) == "abc…"
    assert crop("abc", 4) == "abc"
