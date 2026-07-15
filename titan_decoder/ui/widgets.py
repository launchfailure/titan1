"""Small stdlib-only terminal widgets for the interactive console.

Pure text rendering — no cursor control, no external dependencies — so the
console keeps working over SSH, in Codespaces, and in scripted tests.
"""

from __future__ import annotations

import shutil
from typing import Sequence


def terminal_width(default: int = 88) -> int:
    """Usable terminal width, clamped so layouts stay readable."""
    return max(68, min(120, shutil.get_terminal_size((default, 24)).columns))


def crop(text: object, width: int) -> str:
    """Crop *text* to *width* columns, marking truncation with an ellipsis."""
    text = str(text)
    if len(text) <= width:
        return text
    return text[: max(0, width - 1)] + "…"


def box(title: str, lines: Sequence[str], width: int = 88) -> str:
    """Render a single-line-border box with a title and content lines."""
    width = max(30, width)
    inner = width - 4
    label = f" {crop(title, inner - 2)} "
    out = ["┌" + label + "─" * max(0, width - len(label) - 2) + "┐"]
    out += ["│ " + crop(line, inner).ljust(inner) + " │" for line in lines]
    out += ["└" + "─" * (width - 2) + "┘"]
    return "\n".join(out)


def two_column(
    left_title: str,
    left_lines: Sequence[str],
    right_title: str,
    right_lines: Sequence[str],
    width: int = 88,
    gap: int = 2,
) -> str:
    """Render two boxes side by side, padded to equal height."""
    half = (width - gap) // 2
    left = box(left_title, left_lines, half).splitlines()
    right = box(right_title, right_lines, width - gap - half).splitlines()
    height = max(len(left), len(right))
    left += [" " * half] * (height - len(left))
    right += [" " * (width - gap - half)] * (height - len(right))
    return "\n".join(a + " " * gap + b for a, b in zip(left, right))


def progress_bar(value: float, total: float, width: int = 24) -> str:
    """Render a fixed-width progress bar; out-of-range values are clamped."""
    ratio = 0.0 if total <= 0 else max(0.0, min(1.0, value / total))
    used = round(ratio * width)
    return "[" + "█" * used + "·" * (width - used) + "]"
