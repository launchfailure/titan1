"""Qt stylesheet for the 1536×1024 reference workbench."""

from __future__ import annotations


COLORS = {
    "window": "#050b13",
    "panel": "#08121e",
    "panel_alt": "#091521",
    "border": "#1b3040",
    "border_soft": "#142737",
    "text": "#dce4ec",
    "muted": "#98a7b7",
    "cyan": "#37bdff",
    "green": "#55e17d",
    "yellow": "#f0c84d",
    "violet": "#d17cff",
}


STYLESHEET = r"""
* {
    font-family: "DejaVu Sans Mono", "JetBrains Mono", monospace;
    font-size: 13px;
    color: #dce4ec;
    outline: none;
}
QMainWindow, QWidget#root {
    background: #050b13;
}
QWidget#root {
    border: 1px solid #294055;
}
QWidget#footerWrap {
    background: #050b13;
    border: 0;
}
QFrame#header {
    background: #050b13;
    border-bottom: 1px solid #142737;
}
QLabel#appTitle {
    color: #f2f5f8;
    font-size: 22px;
    font-weight: 700;
    letter-spacing: 1px;
}
QLabel#appVersion {
    color: #9aa9b9;
    font-size: 11px;
}
QLabel#sessionClock {
    color: #9ba8b8;
    font-size: 12px;
}
QPushButton#chipGreen, QPushButton#chipBlue, QPushButton#chipYellow {
    min-height: 29px;
    max-height: 29px;
    padding: 0 12px;
    border-radius: 5px;
    background: #08121d;
    font-size: 12px;
    font-weight: 600;
}
QPushButton#chipGreen { color: #55e17d; border: 1px solid #1d4433; }
QPushButton#chipBlue { color: #70cfff; border: 1px solid #1a3b53; }
QPushButton#chipYellow { color: #f0c84d; border: 1px solid #4b3d1b; }
QPushButton#chipGreen:hover { background: #0d241a; border-color: #337d55; }
QPushButton#chipBlue:hover { background: #0c2232; border-color: #286b93; }
QPushButton#chipYellow:hover { background: #241f0d; border-color: #8d7127; }
QPushButton#chipGreen:pressed, QPushButton#chipBlue:pressed,
QPushButton#chipYellow:pressed { padding-top: 1px; }
QPushButton#windowButton, QPushButton#closeButton {
    min-width: 28px;
    max-width: 28px;
    min-height: 28px;
    max-height: 28px;
    padding: 0;
    border-radius: 5px;
    background: #07111c;
    border: 1px solid #26394b;
}
QPushButton#windowButton:hover { background: #102133; border-color: #3a556c; }
QPushButton#closeButton { border-color: #873528; }
QPushButton#closeButton:hover { background: #421812; }

QFrame#panel, QFrame#sideCard, QFrame#innerCard, QFrame#resultCard {
    background: #08121e;
    border: 1px solid #1b3040;
    border-radius: 6px;
}
QFrame#innerCard, QFrame#resultCard {
    background: #091521;
    border-color: #172b3a;
}
QFrame#panelHeader {
    background: #091522;
    border: 0;
    border-bottom: 1px solid #1b3040;
    border-top-left-radius: 5px;
    border-top-right-radius: 5px;
}
QLabel#panelTitle {
    color: #37bdff;
    font-size: 13px;
    font-weight: 700;
    padding: 0;
    border: 0;
}
QFrame#sideCard QLabel#panelTitle {
    color: #58b9e6;
    font-size: 12px;
    font-weight: 600;
}
QFrame#quickHeader {
    background: #0a1723;
    border: 0;
    border-bottom: 1px solid #1b3040;
    border-top-left-radius: 5px;
    border-top-right-radius: 5px;
}
QLabel#subTitle {
    color: #dbe2ea;
    font-size: 13px;
    font-weight: 700;
    border: 0;
}
QLabel#sectionTitle {
    color: #4bc5ff;
    font-size: 12px;
    font-weight: 700;
}
QLabel#muted { color: #98a7b7; }
QLabel#cyan { color: #37bdff; }
QLabel#decoderCount { color: #37bdff; font-size: 11px; }
QLabel#green { color: #55e17d; }
QLabel#yellow { color: #f0c84d; }
QLabel#violet { color: #d17cff; }
QLabel#decoderStatus {
    font-weight: 500;
}
QLabel#decoderStatus[statusState="success"] { color: #55e17d; }
QLabel#decoderStatus[statusState="inactive"],
QLabel#decoderStatus[statusState="failure"] { color: #ff6b5c; }

QPushButton#navButton {
    min-height: 33px;
    max-height: 33px;
    padding: 0 12px;
    text-align: left;
    border: 0;
    border-radius: 4px;
    background: transparent;
    color: #d3dbe4;
}
QPushButton#navButton:hover { background: #0d2235; color: white; }
QPushButton#navButton:checked {
    background: #102a43;
    color: white;
    border-left: 2px solid #35b9ff;
    border-right: 2px solid #35b9ff;
    font-weight: 600;
}
QLabel#shortcutKey {
    min-width: 25px;
    max-width: 44px;
    min-height: 18px;
    max-height: 18px;
    color: #8d9dad;
    background: #0c1824;
    border: 1px solid #213448;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 400;
    qproperty-alignment: AlignCenter;
}
QLabel#shortcutText {
    color: #8f9dab;
    font-size: 12px;
    font-weight: 400;
}
QPushButton#shortcutRowButton {
    padding: 0;
    text-align: left;
    color: transparent;
    background: transparent;
    border: 0;
    border-radius: 4px;
}
QPushButton#shortcutRowButton:hover { background: #0d2235; }
QFrame#brandCard {
    background: #07111c;
    border: 1px solid #1b3040;
    border-radius: 6px;
}
QLabel#brandName { color: #39bfff; font-size: 20px; font-weight: 700; letter-spacing: 3px; }
QLabel#brandTag {
    color: #2f9dd0;
    font-size: 14px;
    font-weight: 500;
    letter-spacing: 0;
}
QLabel#brandPower {
    color: #a8b3bf;
    font-size: 14px;
    font-weight: 500;
    letter-spacing: -0.3px;
}

QFrame#dropZone {
    background: #08131f;
    border: 1px dashed #526a7e;
    border-radius: 8px;
}
QFrame#dropZone[dragActive="true"] {
    background: #0b2030;
    border: 2px solid #37bdff;
}
QLabel#dropTitle { color: #dce4ec; font-size: 20px; font-weight: 700; }
QLabel#dropHint { color: #bac5d0; font-size: 14px; }
QLabel#dropHintAccent { color: #40dfa0; font-size: 14px; }

QFrame#quickRow {
    min-height: 49px;
    max-height: 49px;
    border-bottom: 1px solid #172939;
    background: transparent;
}
QFrame#quickRow:hover { background: #10243a; }
QLabel#quickText {
    color: #d6dee7;
}
QLabel#quickChevron { color: #748697; font-size: 18px; }
QLabel#iconBoxViolet, QLabel#iconBoxBlue, QLabel#iconBoxGreen, QLabel#iconBoxYellow {
    min-width: 33px; max-width: 33px; min-height: 33px; max-height: 33px;
    border-radius: 5px;
}
QLabel#iconBoxViolet { background: #21142d; border: 1px solid #63378b; }
QLabel#iconBoxBlue { background: #0d2130; border: 1px solid #235d81; }
QLabel#iconBoxGreen { background: #0c2418; border: 1px solid #24653b; }
QLabel#iconBoxYellow { background: #25230d; border: 1px solid #71631b; }

QFrame#metricViolet, QFrame#metricBlue, QFrame#metricGreen, QFrame#metricYellow {
    background: #09131f;
    border-radius: 6px;
}
QFrame#metricViolet { border: 1px solid #8845c7; }
QFrame#metricBlue { border: 1px solid #2278af; }
QFrame#metricGreen { border: 1px solid #28984d; }
QFrame#metricYellow { border: 1px solid #9e8412; }
QFrame#metricHeaderViolet, QFrame#metricHeaderBlue,
QFrame#metricHeaderGreen, QFrame#metricHeaderYellow {
    background: #0b1723;
    border: 0;
    border-bottom: 1px solid rgba(255,255,255,28);
    border-top-left-radius: 5px;
    border-top-right-radius: 5px;
}
QLabel#metricTitleViolet, QLabel#metricTitleBlue, QLabel#metricTitleGreen, QLabel#metricTitleYellow {
    font-size: 13px;
    font-weight: 700;
    padding: 0;
    border: 0;
}
QLabel#metricTitleViolet { color: #d17cff; }
QLabel#metricTitleBlue { color: #56c7ff; }
QLabel#metricTitleGreen { color: #61e27f; }
QLabel#metricTitleYellow { color: #f1d13e; }
QLabel#metricName { color: #c3ccd6; }
QLabel#metricValue { color: #e4e9ee; }
QProgressBar {
    min-height: 7px; max-height: 7px;
    border: 0; border-radius: 3px;
    background: #252e32;
    text-align: right;
}
QProgressBar::chunk { background: #a6ad39; border-radius: 3px; }

QLineEdit {
    min-height: 32px;
    padding: 0 10px;
    color: #dce4ec;
    background: #08131f;
    border: 1px solid #243a4d;
    border-radius: 5px;
    selection-background-color: #13517a;
}
QLineEdit:focus { border-color: #2aaeea; }
QPushButton#primaryButton, QPushButton#secondaryButton, QPushButton#successButton {
    min-height: 31px;
    padding: 0 12px;
    border-radius: 5px;
    background: #091521;
    border: 1px solid #243a4d;
    color: #c8d2dc;
}
QPushButton#primaryButton:hover, QPushButton#secondaryButton:hover { background: #10243a; }
QPushButton#successButton { color: #55e177; border-color: #245d39; }
QPushButton#successButton:hover { background: #0c2717; }

QTreeWidget#decoderList {
    background: #08131f;
    alternate-background-color: #091622;
    border: 1px solid #1b3040;
    border-radius: 5px;
    color: #dce3eb;
    padding: 0;
}
QTreeWidget#decoderList::item { min-height: 29px; border-bottom: 1px solid #152736; }
QTreeWidget#decoderList::item:selected { background: #0f2c46; color: white; }
QScrollBar:vertical {
    background: #07111b; width: 7px; margin: 0;
}
QScrollBar::handle:vertical { background: #47586a; min-height: 30px; border-radius: 3px; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }

QTabWidget::pane {
    background: #08131f;
    border: 1px solid #1a3040;
    border-radius: 5px;
    top: -1px;
}
QTabBar::tab {
    color: #8fb6d0;
    background: #08131f;
    border: 0;
    border-bottom: 2px solid #173044;
    min-height: 34px;
    padding: 0 13px;
    font-size: 11px;
}
QTabBar::tab:selected { color: #6ecfff; border-bottom-color: #2db6ff; }
QTabBar::tab:hover { color: #d8effb; }
QTextEdit, QPlainTextEdit {
    background: #08131f;
    color: #d7e0e8;
    border: 0;
    selection-background-color: #13517a;
}
QLabel#artifactName { color: #eef2f6; font-size: 13px; font-weight: 700; }
QLabel#artifactMeta { color: #b2bfcc; font-size: 11px; }
QListWidget#sampleHistoryList {
    color: #d7e0e8;
    background: #07111c;
    border: 1px solid #192f40;
    border-radius: 5px;
    padding: 3px;
}
QListWidget#sampleHistoryList::item {
    min-height: 45px;
    padding: 5px 7px;
    border-bottom: 1px solid #142737;
}
QListWidget#sampleHistoryList::item:selected {
    color: white;
    background: #10304a;
    border-left: 2px solid #37bdff;
}
QListWidget#sampleHistoryList::item:hover { background: #0d2234; }
QPushButton#historyActionButton, QPushButton#historyRemoveButton {
    min-height: 28px;
    padding: 0 9px;
    color: #aebbc8;
    background: #0a1723;
    border: 1px solid #294055;
    border-radius: 4px;
}
QPushButton#historyActionButton:hover {
    color: #70d3ff;
    border-color: #2788bb;
    background: #0b2435;
}
QPushButton#historyRemoveButton:hover {
    color: #ff8a7d;
    border-color: #8b3f35;
    background: #2a1412;
}
QFrame#summaryCard { background: #0a1723; border: 1px solid #172b3a; border-radius: 5px; }
QFrame#sectionHeader, QFrame#subsectionHeader {
    background: #091622;
    border: 0;
    border-bottom: 1px solid #1b3040;
}
QFrame#sectionHeader {
    border-top-left-radius: 4px;
    border-top-right-radius: 4px;
}
QFrame#subsectionHeader {
    border: 1px solid #1b3040;
    border-radius: 4px;
}
QLabel#summaryTitle { color: #73cfff; font-size: 11px; font-weight: 700; }
QLabel#summaryName { color: #bec9d4; font-size: 11px; }
QLabel#summaryValue { color: #e1e7ed; font-size: 11px; }
QLabel#summaryGood { color: #62df7a; font-size: 11px; }
QLabel#highlightGreen, QLabel#highlightYellow, QLabel#highlightOrange,
QLabel#highlightBlue, QLabel#highlightViolet {
    min-height: 27px; max-height: 27px;
    padding: 0 9px;
    border-radius: 5px;
    font-size: 11px;
}
QLabel#highlightGreen { color: #56df77; border: 1px solid #26683a; background: #0b1f14; }
QLabel#highlightYellow { color: #f0d047; border: 1px solid #6f601b; background: #211e0c; }
QLabel#highlightOrange { color: #ff813d; border: 1px solid #813d1b; background: #25140c; }
QLabel#highlightBlue { color: #66c9ff; border: 1px solid #24618a; background: #0b1c28; }
QLabel#highlightViolet { color: #d393ff; border: 1px solid #65418a; background: #1c1028; }

QFrame#detailSection { background: transparent; border-bottom: 1px solid #1b3040; }
QLabel#detailText { color: #d7e0e8; }
QLabel#detailMeta { color: #8fa2b4; font-size: 11px; }
QFrame#footer {
    background: #07111c;
    border: 1px solid #1a3040;
    border-radius: 5px;
}
QLabel#footerText { color: #a7b4c2; font-size: 12px; }
QToolTip {
    color: #dce4ec;
    background: #0b1723;
    border: 1px solid #294055;
}

/* Titan-owned text/hex input dialog. */
QDialog#titanInputDialog {
    background: #07111c;
    border: 1px solid #2b4d65;
    border-radius: 7px;
}
QFrame#dialogHeader {
    background: #091522;
    border: 0;
    border-bottom: 1px solid #1d3548;
    border-top-left-radius: 7px;
    border-top-right-radius: 7px;
}
QWidget#dialogBody { background: #07111c; }
QLabel#dialogTitle {
    color: #e7edf3;
    font-size: 13px;
    font-weight: 700;
}
QLabel#dialogPrompt { color: #9fb0c0; font-size: 12px; }
QPlainTextEdit#dialogEditor {
    color: #dce4ec;
    background: #050d16;
    border: 1px solid #29465b;
    border-radius: 5px;
    padding: 10px;
    selection-color: white;
    selection-background-color: #13517a;
}
QPlainTextEdit#dialogEditor:focus { border-color: #37bdff; }
QPushButton#dialogCloseButton {
    min-width: 28px; max-width: 28px;
    min-height: 28px; max-height: 28px;
    padding: 0;
    background: #0a1723;
    border: 1px solid #66352f;
    border-radius: 5px;
}
QPushButton#dialogCloseButton:hover { background: #351613; border-color: #b34d40; }
QPushButton#dialogPrimaryButton, QPushButton#dialogSecondaryButton {
    min-width: 96px;
    min-height: 32px;
    padding: 0 14px;
    border-radius: 5px;
    font-weight: 600;
}
QPushButton#dialogSecondaryButton {
    color: #aebbc8;
    background: #0a1723;
    border: 1px solid #294055;
}
QPushButton#dialogSecondaryButton:hover { color: white; background: #10243a; }
QPushButton#dialogPrimaryButton {
    color: #72d4ff;
    background: #0b2435;
    border: 1px solid #2788bb;
}
QPushButton#dialogPrimaryButton:hover {
    color: white;
    background: #123a59;
    border-color: #37bdff;
}
QDialog#recentSamplesDialog {
    background: #07111c;
    border: 1px solid #2b4d65;
    border-radius: 7px;
}
QDialog#titanToolDialog {
    background: #07111c;
    border: 1px solid #2b4d65;
    border-radius: 7px;
}
QPlainTextEdit#toolViewer {
    color: #dce4ec;
    background: #050d16;
    border: 1px solid #29465b;
    border-radius: 5px;
    padding: 12px;
    selection-color: white;
    selection-background-color: #13517a;
}
QTreeWidget#recentSamplesList {
    color: #d3dde6;
    background: #050d16;
    alternate-background-color: #08131f;
    border: 1px solid #29465b;
    border-radius: 5px;
}
QTreeWidget#recentSamplesList::item {
    min-height: 34px;
    padding: 3px 6px;
    border-bottom: 1px solid #142737;
}
QTreeWidget#recentSamplesList::item:selected {
    color: white;
    background: #10304a;
}
QTreeWidget#recentSamplesList QHeaderView::section {
    min-height: 31px;
    padding: 0 7px;
    color: #65caff;
    background: #0a1824;
    border: 0;
    border-right: 1px solid #1b3040;
    border-bottom: 1px solid #29465b;
}
QPushButton#recentDeleteButton {
    min-height: 32px;
    padding: 0 14px;
    color: #ff8a7d;
    background: #241311;
    border: 1px solid #743a32;
    border-radius: 5px;
}
QPushButton#recentDeleteButton:hover {
    color: white;
    background: #421812;
    border-color: #b34d40;
}

/* Titan-owned file dialog: never fall back to the bright desktop theme. */
QFileDialog, QFileDialog QWidget, QMessageBox {
    background: #07111c;
    color: #dce4ec;
}
QFileDialog QLabel { color: #aebbc8; }
QFileDialog QLineEdit, QFileDialog QComboBox {
    min-height: 30px;
    padding: 0 8px;
    color: #dce4ec;
    background: #091521;
    border: 1px solid #294055;
    border-radius: 4px;
}
QFileDialog QComboBox::drop-down {
    width: 24px;
    border: 0;
}
QFileDialog QListView, QFileDialog QTreeView {
    color: #cfd8e1;
    background: #08131f;
    alternate-background-color: #0a1723;
    border: 1px solid #1b3040;
    border-radius: 4px;
    selection-color: white;
    selection-background-color: #123a59;
}
QFileDialog QHeaderView::section {
    min-height: 27px;
    padding-left: 7px;
    color: #7fcfff;
    background: #0b1824;
    border: 0;
    border-right: 1px solid #1b3040;
    border-bottom: 1px solid #1b3040;
}
QFileDialog QToolButton {
    min-width: 30px;
    min-height: 30px;
    padding: 0;
    color: #a9b8c8;
    background: #091521;
    border: 1px solid #294055;
    border-radius: 4px;
}
QFileDialog QToolButton:hover { background: #102a43; color: white; }
QFileDialog QPushButton, QMessageBox QPushButton {
    min-width: 88px;
    min-height: 30px;
    padding: 0 12px;
    color: #cbd6df;
    background: #0a1824;
    border: 1px solid #294055;
    border-radius: 4px;
}
QFileDialog QPushButton:hover, QMessageBox QPushButton:hover {
    color: white;
    background: #123a59;
    border-color: #37bdff;
}
QFileDialog QPushButton:default {
    color: #60e184;
    border-color: #2c7545;
    background: #0b2517;
}
QFileDialog QSplitter::handle { background: #142737; }
"""
