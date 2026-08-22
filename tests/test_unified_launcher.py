from __future__ import annotations

import sys
import tomllib

import pytest

from titan_decoder import launcher


def test_package_registers_only_the_titan_command() -> None:
    from pathlib import Path

    with (Path(__file__).parents[1] / "pyproject.toml").open("rb") as stream:
        project = tomllib.load(stream)["project"]
    assert project["scripts"] == {"titan": "titan_decoder.launcher:main"}
    assert project["dependencies"] == []
    assert project["optional-dependencies"]["desktop-ui"] == [
        "PySide6>=6.6,<7",
        "psutil>=5,<8",
    ]


def test_no_arguments_open_the_desktop(monkeypatch: pytest.MonkeyPatch) -> None:
    opened: list[list[str]] = []
    monkeypatch.setattr(launcher, "_desktop", lambda args: opened.append(args) or 0)
    monkeypatch.setattr(sys, "argv", ["titan"])
    assert launcher.main() == 0
    assert opened == [[]]


def test_help_describes_unified_advanced_subcommands(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["titan", "--help"])
    assert launcher.main() == 0
    output = capsys.readouterr().out
    assert "titan cli [options]" in output
    assert "titan server [options]" in output


def test_unknown_subcommand_fails_cleanly(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["titan", "missing"])
    assert launcher.main() == 2
    assert "Unknown Titan command: missing" in capsys.readouterr().err


def test_cli_subcommand_forwards_arguments(monkeypatch: pytest.MonkeyPatch) -> None:
    received: list[str] = []

    def fake_main() -> int:
        received.extend(sys.argv)
        return 17

    monkeypatch.setattr("titan_decoder.cli.main", fake_main)
    monkeypatch.setattr(sys, "argv", ["titan", "cli", "--doctor"])
    assert launcher.main() == 17
    assert received == ["titan cli", "--doctor"]
