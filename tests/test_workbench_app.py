"""Tests for the Analyst Workbench menu app, driven with injected I/O."""

import io
import json

from titan_decoder.interactive import Style
from titan_decoder.workbench.app import AnalystWorkbench

from test_workbench import sample_report


def _write_report(tmp_path, name="report.json", data=None):
    path = tmp_path / name
    path.write_text(json.dumps(data if data is not None else sample_report()))
    return path


def _run(script):
    it = iter(script)
    out = io.StringIO()
    app = AnalystWorkbench(input_fn=lambda prompt="": next(it), out=out, style=Style(False))
    rc = app.run()
    return rc, out.getvalue(), app


def test_quit_and_banner():
    rc, text, _ = _run(["q"])
    assert rc == 0
    assert "ANALYST WORKBENCH" in text
    assert "Workbench closed." in text


def test_eof_exits_cleanly():
    def eof(prompt=""):
        raise EOFError

    out = io.StringIO()
    app = AnalystWorkbench(input_fn=eof, out=out, style=Style(False))
    assert app.run() == 0
    assert "Workbench closed." in out.getvalue()


def test_views_require_a_report():
    rc, text, _ = _run(["3", "q"])
    assert "Select or load a report first." in text


def test_load_directory_and_explore(tmp_path):
    _write_report(tmp_path, "a.json")
    second = sample_report()
    second["meta"]["analysis_id"] = "case-b"
    _write_report(tmp_path, "b.json", second)

    rc, text, app = _run(
        [
            "1", str(tmp_path),          # load directory
            "2", "2",                    # select report 2
            "3",                          # overview
            "4", "base64",               # decode tree filtered
            "6", "",                     # IOC browser, no filter
            "7", "high",                 # detections filtered
            "8", "",                     # timeline
            "9", "",                     # evidence browser
            "c",                          # correlation view
            "q",
        ]
    )
    assert rc == 0
    assert "Loaded 2 report(s)." in text
    assert "Analysis ID       case-b" in text
    assert "DECODE_Base64" in text
    assert "c2.test" in text
    assert "X-1" in text
    assert "dns_query" in text
    assert "Top pivots" in text
    assert "case-a ↔ case-b" in text
    assert app.active_index == 1


def test_graph_viewer_node_detail_and_export(tmp_path):
    report_path = _write_report(tmp_path)
    graph_out = tmp_path / "graph.mmd"
    rc, text, _ = _run(
        [
            "1", str(report_path),
            "5",                          # graph viewer
            "1",                          # node detail for id 1
            "x", "mermaid", str(graph_out),
            "b",
            "q",
        ]
    )
    assert rc == 0
    assert "Parent            0" in text
    assert "Exported mermaid graph" in text
    assert graph_out.exists()


def test_global_search(tmp_path):
    report_path = _write_report(tmp_path)
    rc, text, _ = _run(["1", str(report_path), "/", "c2.test", "q"])
    assert rc == 0
    assert "hit(s)" in text
    assert "report.json" in text


def test_notes_tags_status_and_workspace_roundtrip(tmp_path):
    report_path = _write_report(tmp_path)
    workspace_path = tmp_path / "ws.json"
    rc, text, _ = _run(
        [
            "1", str(report_path),
            "n", "1", "priority",         # add tag
            "n", "4", "in-progress",      # set status
            "s", str(workspace_path),     # save workspace
            "q",
        ]
    )
    assert rc == 0
    assert "Saved workspace" in text
    saved = json.loads(workspace_path.read_text())
    assert saved["schema_version"] == "analyst-workspace-v1.0"
    assert saved["entries"][0]["tags"] == ["priority"]
    assert saved["entries"][0]["status"] == "in-progress"

    # Reopen the workspace in a fresh app: reports reload from stored paths.
    rc, text, app = _run(["o", str(workspace_path), "3", "q"])
    assert rc == 0
    assert "Opened" in text
    assert "Analysis ID       case-a" in text


def test_export_menu_writes_csv_and_bundle(tmp_path):
    report_path = _write_report(tmp_path)
    csv_path = tmp_path / "iocs.csv"
    bundle_path = tmp_path / "case.zip"
    rc, text, _ = _run(
        [
            "1", str(report_path),
            "e", "1", str(csv_path),
            "e", "3", str(bundle_path),
            "q",
        ]
    )
    assert rc == 0
    assert "c2.test" in csv_path.read_text()
    assert bundle_path.exists()


def test_bad_report_is_skipped_not_fatal(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    good = _write_report(tmp_path, "good.json")
    rc, text, _ = _run(["1", str(tmp_path), "q"])
    assert rc == 0
    assert "Skipped" in text and str(bad) in text
    assert "Loaded 1 report(s)." in text
    assert good.exists()


def test_unknown_option_keeps_loop_alive():
    rc, text, _ = _run(["z", "q"])
    assert rc == 0
    assert "Unknown option." in text
