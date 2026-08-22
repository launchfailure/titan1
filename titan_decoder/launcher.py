"""Unified ``titan`` application entry point.

The native desktop workbench is the default product experience.  Advanced
terminal and service interfaces remain available as explicit subcommands so
the installed package exposes one executable without removing automation
capabilities.
"""

from __future__ import annotations

import sys
from collections.abc import Callable

from titan_decoder import __version__ as TITAN_VERSION


def _run(entry_point: Callable[[], object], arguments: list[str]) -> int:
    sys.argv = [f"titan {sys.argv[1]}", *arguments]
    result = entry_point()
    return result if isinstance(result, int) else 0


def _desktop(arguments: list[str]) -> int:
    from titan_decoder.desktop_ui.app import main

    sys.argv = ["titan", *arguments]
    main()
    return 0


def _usage() -> str:
    return """Titan Forensic Workbench

Usage:
  titan                         Open the native desktop workbench
  titan gui                     Open the native desktop workbench explicitly
  titan cli [options]           Run the advanced analysis CLI
  titan tui [options]           Open the terminal workbench
  titan workbench [options]     Explore completed reports in a terminal
  titan analyst [options]       Query completed reports
  titan server [options]        Run the local API or worker
  titan plugin-catalog [args]   Validate the community plugin catalog

Use `titan <subcommand> --help` for advanced options.
"""


def main() -> int:
    arguments = sys.argv[1:]
    if not arguments:
        return _desktop([])

    command, *remaining = arguments
    if command in {"-h", "--help", "help"}:
        print(_usage())
        return 0
    if command in {"-V", "--version"}:
        print(f"titan {TITAN_VERSION}")
        return 0
    if command == "gui":
        return _desktop(remaining)
    if command == "cli":
        from titan_decoder.cli import main

        return _run(main, remaining)
    if command == "tui":
        from titan_decoder.workbench_ui.app import main

        return _run(main, remaining)
    if command == "workbench":
        from titan_decoder.workbench.app import main

        return _run(main, remaining)
    if command == "analyst":
        from titan_decoder.analyst.cli import main

        return _run(main, remaining)
    if command == "server":
        from titan_decoder.server.app import main

        return _run(main, remaining)
    if command == "plugin-catalog":
        from titan_decoder.ecosystem.catalog_cli import main

        return _run(main, remaining)

    print(f"Unknown Titan command: {command}\n", file=sys.stderr)
    print(_usage(), file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
