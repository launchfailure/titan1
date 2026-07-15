import pytest


def test_workbench_app_imports_when_textual_is_installed():
    pytest.importorskip("textual")
    from titan_decoder.workbench_ui.app import TitanWorkbenchApp

    assert TitanWorkbenchApp.TITLE == "Titan Forensic Workbench"
    assert "dashboard" in TitanWorkbenchApp.ROUTES
    assert "analyst" in TitanWorkbenchApp.ROUTES
