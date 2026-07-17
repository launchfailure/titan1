"""Textual front end for Titan's deterministic forensic workbench.

The package stays importable without the optional Textual dependency; the
application class is loaded lazily when requested.
"""

from __future__ import annotations

from typing import Any

__all__ = ["TitanWorkbenchApp", "main"]


def __getattr__(name: str) -> Any:
    if name in {"TitanWorkbenchApp", "main"}:
        from .app import TitanWorkbenchApp, main

        return TitanWorkbenchApp if name == "TitanWorkbenchApp" else main
    raise AttributeError(name)
