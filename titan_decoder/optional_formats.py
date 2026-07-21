"""Shared readiness checks for Titan's optional format libraries."""

from __future__ import annotations

import importlib
from typing import Any, Callable


OPTIONAL_FORMAT_MODULES = (
    "brotli",
    "zstandard",
    "py7zr",
    "rarfile",
    "pycdlib",
    "cabarchive",
)

FORMAT_DECODER_REQUIREMENTS = {
    "Brotli": "brotli",
    "Zstandard": "zstandard",
}

FORMAT_INSTALL_HINT = "python -m pip install 'titan-decoder[formats]'"


def optional_format_availability(
    importer: Callable[[str], Any] = importlib.import_module,
) -> dict[str, bool]:
    """Import each library so broken native installs are reported as unavailable."""
    available: dict[str, bool] = {}
    for module in OPTIONAL_FORMAT_MODULES:
        try:
            importer(module)
            available[module] = True
        except Exception:
            available[module] = False
    return available


def optional_format_status(
    importer: Callable[[str], Any] = importlib.import_module,
) -> dict[str, Any]:
    """Return a stable, user-facing readiness summary for the ``formats`` extra."""
    modules = optional_format_availability(importer)
    missing = sorted(module for module, present in modules.items() if not present)
    return {
        "ready": not missing,
        "modules": modules,
        "available": sorted(module for module, present in modules.items() if present),
        "missing": missing,
        "install_hint": FORMAT_INSTALL_HINT,
    }
