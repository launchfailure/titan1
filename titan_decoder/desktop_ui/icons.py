"""Small vector icon set used by the native workbench.

The artwork is embedded SVG so it stays sharp at every display scale and does
not depend on an icon font being installed in Debian.
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QByteArray, Qt
from PySide6.QtGui import QIcon, QPainter, QPixmap
from PySide6.QtSvg import QSvgRenderer


_ASSET_DIRECTORY = Path(__file__).with_name("assets")


_PATHS: dict[str, str] = {
    "shield": (
        '<path d="M12 1.3 21.5 4.2v7.2c0 5.3-3.7 9.3-9.5 11.3-5.8-2-9.5-6-9.5-11.3V4.2z"/>'
        '<path opacity=".48" d="M12 4.2 18.5 6v5.2c0 3.8-2.3 6.6-6.5 8.3-4.2-1.7-6.5-4.5-6.5-8.3V6z"/>'
        '<path d="M6.2 7.2 12 5.4l5.8 1.8M12 5.4v14"/>'
    ),
    "home": '<path d="m3 11 9-8 9 8"/><path d="M5 10v10h14V10M9 20v-6h6v6"/>',
    "search": '<circle cx="10.5" cy="10.5" r="7.5"/><path d="m16 16 5 5"/>',
    "code": '<path d="m8 5-6 7 6 7M16 5l6 7-6 7M14 3l-4 18"/>',
    "folder": '<path d="M3 6h7l2 2h9v11H3z"/><path d="M3 6V4h7l2 2"/>',
    "chip": (
        '<rect x="6" y="6" width="12" height="12" rx="1"/>'
        '<path d="M9 1v4M15 1v4M9 19v4M15 19v4M1 9h4M1 15h4M19 9h4M19 15h4"/>'
    ),
    "file": '<path d="M6 2h8l5 5v15H6z"/><path d="M14 2v6h5M9 13h7M9 17h7"/>',
    "graph": (
        '<circle cx="5" cy="5" r="2"/><circle cx="19" cy="5" r="2"/>'
        '<circle cx="5" cy="19" r="2"/><circle cx="19" cy="19" r="2"/>'
        '<circle cx="12" cy="12" r="2"/><path d="m6.5 6.5 4 4m7-4-4 4m-7 7 4-4m7 4-4-4"/>'
    ),
    "puzzle": (
        '<path d="M9 3h4v4a2 2 0 1 0 4 0V3h4v6h-4a2 2 0 1 0 0 4h4v8h-8v-4a2 2 0 1 0-4 0v4H3v-8h4a2 2 0 1 0 0-4H3V3z"/>'
    ),
    "target": '<circle cx="12" cy="12" r="8"/><circle cx="12" cy="12" r="3"/><path d="M12 1v4M12 19v4M1 12h4M19 12h4"/>',
    "settings": '<circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3M5 5l2 2M17 17l2 2M19 5l-2 2M7 17l-2 2"/><circle cx="12" cy="12" r="8"/>',
    "book": '<path d="M3 4h7a3 3 0 0 1 3 3v14a3 3 0 0 0-3-3H3zM21 4h-7a3 3 0 0 0-3 3v14a3 3 0 0 1 3-3h7z"/>',
    "upload": (
        '<path d="M12 18.5V10m-3.5 3.5L12 10l3.5 3.5"/>'
        '<path d="M6 21C3.8 21 2 19.2 2 17s1.6-4 3.8-4.4C6.4 8.3 8.8 5 12 5s5.6 3.3 6.2 7.6C20.4 13 22 14.8 22 17s-1.8 4-4 4Z"/>'
    ),
    "clipboard": '<rect x="5" y="4" width="14" height="18" rx="2"/><path d="M9 4V2h6v2M9 10h6M9 14h6M9 18h4"/>',
    "hash": '<path d="M10 3 7 21M17 3l-3 18M4 9h16M3 15h16"/>',
    "clock": '<circle cx="12" cy="12" r="9"/><path d="M12 7v6l4 2"/>',
    "copy": '<rect x="8" y="8" width="12" height="13" rx="2"/><path d="M16 8V4H4v13h4"/>',
    "save": '<path d="M4 3h14l3 3v15H4z"/><path d="M8 3v6h9V3M8 21v-7h9v7"/>',
    "play": '<path d="m8 4 12 8-12 8z"/>',
    "document": '<path d="M6 2h9l4 4v16H6z"/><path d="M15 2v5h5M9 12h7M9 16h7"/>',
    "chevron": '<path d="m9 5 7 7-7 7"/>',
    "check": '<path d="m4 12 5 5L20 6"/>',
    "minus": '<path d="M5 12h14"/>',
    "square": '<rect x="5" y="5" width="14" height="14"/>',
    "close": '<path d="m6 6 12 12M18 6 6 18"/>',
}


def svg(name: str, color: str = "#a9b8c8", *, fill: str = "none") -> bytes:
    paths = _PATHS[name]
    source = (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" '
        f'fill="{fill}" stroke="{color}" stroke-width="1.7" '
        'stroke-linecap="round" stroke-linejoin="round">'
        f"{paths}</svg>"
    )
    return source.encode("utf-8")


def icon(name: str, color: str = "#a9b8c8", *, fill: str = "none") -> QIcon:
    value = QIcon()
    for size in (16, 20, 24, 32, 40, 48, 64, 128, 256):
        value.addPixmap(pixmap(name, color, size=size, fill=fill))
    return value


def pixmap(
    name: str,
    color: str = "#a9b8c8",
    *,
    size: int = 24,
    fill: str = "none",
) -> QPixmap:
    if name == "shield":
        artwork = QPixmap(str(_ASSET_DIRECTORY / "titan-shield.png"))
        if not artwork.isNull():
            return artwork.scaled(
                size,
                size,
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation,
            )
    value = QPixmap(size, size)
    value.fill(Qt.GlobalColor.transparent)
    renderer = QSvgRenderer(QByteArray(svg(name, color, fill=fill)))
    painter = QPainter(value)
    renderer.render(painter)
    painter.end()
    return value


def asset_pixmap(filename: str, *, width: int | None = None) -> QPixmap:
    """Load approved raster branding without reconstructing its geometry."""
    artwork = QPixmap(str(_ASSET_DIRECTORY / filename))
    if artwork.isNull() or width is None or artwork.width() == width:
        return artwork
    return artwork.scaledToWidth(width, Qt.TransformationMode.SmoothTransformation)
