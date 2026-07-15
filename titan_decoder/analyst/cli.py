"""The ``titan-analyst`` command: grounded Q&A over completed reports.

The AI analyst is optional by design — the default backend is
``deterministic``, which needs no model and produces citation-carrying
answers straight from the evidence ledger. Enabling a model is an explicit
choice (``--backend local-openai``), and endpoints are loopback-only unless
``--allow-remote-endpoint`` is passed.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .backend import LocalOpenAIBackend
from .engine import AnalystEngine


def _load_reports(paths) -> list[dict]:
    reports = []
    for path in paths:
        path = Path(path)
        candidates = sorted(path.glob("*.json")) if path.is_dir() else [path]
        for candidate in candidates:
            try:
                data = json.loads(candidate.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                print(f"Skipped {candidate}: {exc}", file=sys.stderr)
                continue
            if isinstance(data, dict):
                reports.append(data)
    return reports


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="titan-analyst",
        description="Grounded Local AI Analyst over completed Titan reports",
    )
    parser.add_argument(
        "--report",
        action="append",
        type=Path,
        required=True,
        help="Titan report file or directory of reports (repeatable)",
    )
    parser.add_argument("--ask", help="Ask one question and exit")
    parser.add_argument(
        "--backend",
        choices=["deterministic", "local-openai"],
        default="deterministic",
        help="Answer backend (default: deterministic — no model required)",
    )
    parser.add_argument(
        "--endpoint",
        default="http://127.0.0.1:8080/v1/chat/completions",
        help="OpenAI-compatible chat-completions endpoint (loopback by default)",
    )
    parser.add_argument("--model", default="local-model", help="Model name to request")
    parser.add_argument(
        "--timeout", type=float, default=60.0, help="Backend request timeout (seconds)"
    )
    parser.add_argument(
        "--max-tokens", type=int, default=800, help="Backend output token bound"
    )
    parser.add_argument(
        "--allow-remote-endpoint",
        action="store_true",
        help="Permit a non-loopback endpoint (explicit opt-in; sends evidence off-host)",
    )
    parser.add_argument(
        "--json", action="store_true", help="Emit the structured response JSON"
    )
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    reports = _load_reports(args.report)
    if not reports:
        print("No Titan reports were loaded.", file=sys.stderr)
        return 2

    backend = None
    if args.backend == "local-openai":
        if args.allow_remote_endpoint:
            print(
                "Warning: remote AI endpoint enabled — ledger evidence will "
                "leave this host.",
                file=sys.stderr,
            )
        try:
            backend = LocalOpenAIBackend(
                args.endpoint,
                args.model,
                timeout_seconds=args.timeout,
                max_tokens=args.max_tokens,
                allow_non_loopback=args.allow_remote_endpoint,
            )
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 2

    engine = AnalystEngine(reports, backend=backend)

    def answer(question: str) -> None:
        response = engine.ask(question)
        print(json.dumps(response.to_dict(), indent=2) if args.json else response.answer)

    if args.ask:
        answer(args.ask)
        return 0

    print(f"Titan Local AI Analyst — {len(reports)} report(s), backend: {args.backend}.")
    print("Type a question, or 'quit' to exit.")
    while True:
        try:
            question = input("analyst> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if question.lower() in {"quit", "exit", "q"}:
            break
        if not question:
            continue
        answer(question)
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
