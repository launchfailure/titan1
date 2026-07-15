import pytest


def test_integrated_app_imports_with_textual():
    pytest.importorskip("textual")
    from titan_decoder.workbench_ui.app import TitanWorkbenchApp

    assert TitanWorkbenchApp.TITLE == "Titan Forensic Workbench"
