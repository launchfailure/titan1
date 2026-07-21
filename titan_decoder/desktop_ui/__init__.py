"""Native desktop front end for the Titan forensic engine."""

from __future__ import annotations

from typing import Any

__all__ = ["TitanDesktopWindow", "main"]


def __getattr__(name: str) -> Any:
    if name in __all__:
        from .app import TitanDesktopWindow, main

        return TitanDesktopWindow if name == "TitanDesktopWindow" else main
    raise AttributeError(name)
