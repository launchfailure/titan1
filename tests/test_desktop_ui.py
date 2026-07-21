import os
from pathlib import Path

import pytest


os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6")

from PySide6.QtCore import QMimeData, QUrl, Qt
from PySide6.QtTest import QSignalSpy
from PySide6.QtWidgets import QApplication, QFrame, QLabel

from titan_decoder.desktop_ui.app import TitanDesktopWindow
from titan_decoder.desktop_ui.debian_services import windows_path_to_wsl
from titan_decoder.desktop_ui.icons import asset_pixmap, svg
from titan_decoder.desktop_ui.sample_archive import SampleArchive
from titan_decoder.desktop_ui.widgets import (
    DropZone,
    NavigationColumn,
    RecentSamplesDialog,
    TitanMultilineDialog,
    TitanTextDialog,
)
from titan_decoder.workbench_ui.models import AnalysisSnapshot


@pytest.fixture(scope="module")
def qt_app():
    return QApplication.instance() or QApplication([])


def test_desktop_window_uses_reference_geometry(qt_app):
    window = TitanDesktopWindow()
    assert (window.width(), window.height()) == (1536, 1024)
    assert window.navigation.width() == 224
    assert window.decoders.parentWidget().width() == 396
    assert window.investigation.height() == 313
    assert window.decoders.height() == 496
    assert window.header.title_label.text() == "TITAN FORENSIC WORKBENCH"
    assert window.header.title_label.width() == 370
    window.close()


def test_drop_zone_accepts_local_files(qt_app, tmp_path):
    source = tmp_path / "evidence.bin"
    source.write_bytes(b"payload")
    mime = QMimeData()
    mime.setUrls([QUrl.fromLocalFile(str(source))])
    assert mime.hasUrls()
    assert Path(mime.urls()[0].toLocalFile()) == source
    drop_zone = DropZone()
    assert drop_zone.acceptDrops()
    assert drop_zone.cursor().shape() == Qt.CursorShape.ArrowCursor


def test_approved_titan_wordmark_asset_loads(qt_app):
    artwork = asset_pixmap("titan-wordmark.png")
    assert not artwork.isNull()
    assert (artwork.width(), artwork.height()) == (165, 66)


def test_upload_arrow_is_drawn_inside_cloud():
    artwork = svg("upload").decode("utf-8")
    assert 'M12 18.5V10m-3.5 3.5L12 10l3.5 3.5' in artwork
    assert 'M6 21C3.8 21 2 19.2 2 17' in artwork
    assert "M12 16V4" not in artwork


def test_multiline_input_dialog_is_titan_owned(qt_app):
    parent = TitanDesktopWindow()
    dialog = TitanMultilineDialog(parent, "Analyze Input", "Paste evidence:")
    assert dialog.objectName() == "titanInputDialog"
    assert dialog.editor.objectName() == "dialogEditor"
    assert (dialog.width(), dialog.height()) == (520, 382)
    dialog.close()
    parent.close()


def test_hidden_latest_sample_remains_in_recent_manager(qt_app, tmp_path):
    window = TitanDesktopWindow()
    window.archive = SampleArchive(tmp_path / "history")
    record = window.archive.archive_bytes(b"sample", "previous.txt")
    snapshot = AnalysisSnapshot(
        source_name="previous.txt",
        source_size=6,
        report={"analysis_outcome": {"status": "analyzed"}},
    )
    window.archive.attach_snapshot(record.id, snapshot)
    window.current_sample_id = record.id
    window._refresh_sample_history()
    assert window.results.history.count() == 1

    window._remove_from_latest(record.id)

    assert window.archive.records(include_hidden=False) == []
    assert len(window.archive.records(include_hidden=True)) == 1
    assert window.current_sample_id is None
    assert window.current_data == b""
    assert window.snapshot.source_name == "No investigation loaded"
    assert window.results.artifact_name.text() == "No investigation loaded"
    manager = RecentSamplesDialog(
        window,
        window.archive.records(include_hidden=True),
    )
    assert manager.samples.topLevelItemCount() == 1
    assert manager.samples.topLevelItem(0).text(3) == "Archived"
    manager.close()

    window._open_archived_sample(record.id)

    assert window.archive.records(include_hidden=False)[0].id == record.id
    assert window.snapshot.source_name == "previous.txt"
    assert window.current_data == b"sample"
    window.close()


def test_windows_drop_paths_follow_the_host_platform():
    expected = (
        Path(r"C:\Users\Analyst\Desktop\sample evidence.bin")
        if os.name == "nt"
        else Path("/mnt/c/Users/Analyst/Desktop/sample evidence.bin")
    )
    assert TitanDesktopWindow._normalize_external_path(
        r'"C:\Users\Analyst\Desktop\sample evidence.bin"'
    ) == expected
    assert TitanDesktopWindow._normalize_external_path(
        "file:///C:/Users/Analyst/Desktop/sample%20evidence.bin"
    ) == expected


def test_windows_path_translates_for_debian_backend():
    assert windows_path_to_wsl(
        r"C:\Users\Analyst\Desktop\sample evidence.bin"
    ) == "/mnt/c/Users/Analyst/Desktop/sample evidence.bin"


def test_decoder_selection_updates_details(qt_app):
    window = TitanDesktopWindow()
    window._select_decoder(1)
    assert window.selected_decoder == 1
    assert "Recursive" in window.decoder_details.decoder_name.text()
    window.close()


def test_decoder_status_uses_red_for_inactive_and_failed(qt_app):
    window = TitanDesktopWindow()
    window.show()
    qt_app.processEvents()

    status = window.decoder_details.status_text
    assert status.text() == "Not Running"
    assert status.property("statusState") == "inactive"
    assert status.palette().color(status.foregroundRole()).name() == "#ff6b5c"

    window.decoder_details.refresh_snapshot(
        AnalysisSnapshot(decoder_success=False)
    )
    qt_app.processEvents()
    assert status.text() == "Decode Failed"
    assert status.property("statusState") == "failure"
    assert status.palette().color(status.foregroundRole()).name() == "#ff6b5c"

    window.decoder_details.refresh_snapshot(
        AnalysisSnapshot(decoder_success=True)
    )
    qt_app.processEvents()
    assert status.text() == "Successfully Decoded!"
    assert status.property("statusState") == "success"
    assert status.palette().color(status.foregroundRole()).name() == "#55e17d"
    window.close()


def test_every_navigation_and_shortcut_row_is_clickable(qt_app):
    navigation = NavigationColumn()
    navigation.show()
    qt_app.processEvents()
    spy = QSignalSpy(navigation.route_selected)

    expected_navigation = [row[2] for row in NavigationColumn._NAVIGATION]
    for route in expected_navigation:
        navigation.nav_buttons[route].click()
    assert [spy.at(index)[0] for index in range(spy.count())] == expected_navigation

    spy = QSignalSpy(navigation.route_selected)
    expected_shortcuts = [row[2] for row in NavigationColumn._SHORTCUTS]
    for route in expected_shortcuts:
        assert navigation.shortcut_buttons[route].height() == 27
        assert (
            navigation.shortcut_buttons[route].cursor().shape()
            == Qt.CursorShape.ArrowCursor
        )
        navigation.shortcut_buttons[route].click()
    assert [spy.at(index)[0] for index in range(spy.count())] == expected_shortcuts
    assert navigation.shortcut_key_labels["dashboard"].width() == 25
    assert navigation.shortcut_key_labels["refresh"].width() == 40
    assert navigation.shortcut_text_labels["dashboard"].x() == 39
    assert navigation.shortcut_text_labels["refresh"].x() == 50
    navigation.close()


def test_shortcut_labels_keep_muted_reference_color(qt_app):
    window = TitanDesktopWindow()
    window.show()
    qt_app.processEvents()
    label = window.navigation.shortcut_text_labels["dashboard"]
    color = label.palette().color(label.foregroundRole()).name()
    assert color == "#8f9dab"
    window.close()


def test_all_documented_keyboard_shortcuts_dispatch(qt_app, monkeypatch):
    window = TitanDesktopWindow()
    seen = []
    monkeypatch.setattr(window, "_route_selected", seen.append)
    expected = {
        "H": "dashboard",
        "A": "investigation",
        "D": "decoders",
        "R": "reports",
        "P": "plugins",
        "S": "settings",
        "?": "help",
        "Ctrl+L": "refresh",
        "Q": "quit",
    }
    for key, route in expected.items():
        window.keyboard_shortcuts[key].activated.emit()
        assert seen[-1] == route
    window.close()


def test_secondary_workspace_routes_dispatch_to_real_actions(qt_app, monkeypatch):
    window = TitanDesktopWindow()
    calls = []
    handlers = {
        "reports": "_show_recent_samples",
        "memory": "_show_memory_analysis",
        "file-analysis": "_show_file_analysis",
        "correlation": "_show_correlation",
        "plugins": "_show_plugins",
        "iocs": "_show_ioc_manager",
        "settings": "_show_settings",
        "help": "_show_help",
        "refresh": "_refresh_workspace",
    }
    for route, method_name in handlers.items():
        monkeypatch.setattr(
            window,
            method_name,
            lambda value=route: calls.append(value),
        )
    for route in handlers:
        window._route_selected(route)
    assert calls == list(handlers)
    window.close()


def test_tool_dialog_is_titan_owned_and_read_only(qt_app):
    parent = TitanDesktopWindow()
    dialog = TitanTextDialog(parent, "IOC Manager", "Summary", "No indicators")
    assert dialog.objectName() == "titanToolDialog"
    assert dialog.viewer.isReadOnly()
    assert dialog.viewer.toPlainText() == "No indicators"
    dialog.close()
    parent.close()


def test_header_chips_change_live_engine_state(qt_app, monkeypatch):
    window = TitanDesktopWindow()

    assert window.header.profile_chip.text() == "PROFILE:  FAST"
    window.header.profile_chip.click()
    assert window.services.state.profile == "full"
    assert window.header.profile_chip.text() == "PROFILE:  FULL"
    assert window.status_cards.state.profile == "full"

    assert not window.services.state.aggressive
    window.header.aggressive_chip.click()
    assert window.services.state.aggressive
    assert window.header.aggressive_chip.text() == "AGGRESSIVE:  ON"

    monkeypatch.setattr(window, "_confirm_network_enable", lambda: True)
    assert window.services.state.offline
    window.header.network_chip.click()
    assert not window.services.state.offline
    assert window.header.network_chip.text() == "NETWORK:  ONLINE"
    window.header.network_chip.click()
    assert window.services.state.offline
    assert window.header.network_chip.text() == "NETWORK:  OFFLINE"
    window.close()


def test_network_chip_respects_cancel(qt_app, monkeypatch):
    window = TitanDesktopWindow()
    monkeypatch.setattr(window, "_confirm_network_enable", lambda: False)
    window.header.network_chip.click()
    assert window.services.state.offline
    assert window.header.network_chip.text() == "NETWORK:  OFFLINE"
    window.close()


def test_online_warning_explains_external_data_risk():
    warning = TitanDesktopWindow.NETWORK_WARNING
    assert "external services" in warning
    assert "sample-derived data" in warning
    assert "does not automatically upload the evidence file" in warning
    assert "third-party plugins" in warning


def test_major_sections_use_distinct_header_rails(qt_app):
    window = TitanDesktopWindow()
    assert window.investigation.header.objectName() == "panelHeader"
    assert window.results.header.objectName() == "panelHeader"
    assert window.decoders.header.objectName() == "panelHeader"
    assert window.status_cards.session.findChild(QFrame, "metricHeaderViolet")
    assert window.status_cards.system.findChild(QFrame, "metricHeaderBlue")
    assert window.status_cards.engine.findChild(QFrame, "metricHeaderGreen")
    assert window.status_cards.resources.findChild(QFrame, "metricHeaderYellow")
    assert len(window.results.summary.findChildren(QFrame, "sectionHeader")) == 3
    assert window.results.findChild(QFrame, "subsectionHeader")
    window.close()


def test_brand_card_uses_aligned_reference_sizing(qt_app):
    window = TitanDesktopWindow()
    brand = window.navigation.findChild(QFrame, "brandCard")
    tag = brand.findChild(QLabel, "brandTag")
    power = brand.findChild(QLabel, "brandPower")
    logo_labels = [
        label
        for label in brand.findChildren(QLabel)
        if label.pixmap() is not None and not label.pixmap().isNull()
    ]
    assert brand.height() == 147
    assert logo_labels[0].pixmap().width() == 183
    assert tag.height() == power.height() == 18
    assert tag.y() == 89
    assert power.y() == 113
    assert tag.contentsMargins().left() == power.contentsMargins().left() == 12
    window.close()
