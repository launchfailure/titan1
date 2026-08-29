#!/usr/bin/env python3
"""Time-bounded adversarial campaign over Titan's public-facing surfaces."""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import random
import sys
from tempfile import TemporaryDirectory
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fuzz.fuzz_decoders import load_corpus, mutate  # noqa: E402
from fuzz.surface_invariants import (  # noqa: E402
    SURFACES,
    SurfaceInvariantError,
    check_surfaces,
)

STRUCTURED_SEEDS = (
    b'{"timestamp":"2026-01-01T00:00:00Z","query":"example.test"}\n',
    (
        b'{"schema_version":"1.0","id":"fuzz.plugin","name":"Fuzz",'
        b'"version":"1.0.0","api_version":"1.0","entry_point":"plugin:Fuzz",'
        b'"capabilities":["decoder"]}'
    ),
    (
        b'{"context":{"max_input_bytes":4096,"max_output_bytes":4096},'
        b'"payload":{"data":"ZnV6eg=="}}'
    ),
    b'{"nodes":[],"iocs":{},"timeline":[],"detections":[]}',
    b'{"name":"Fuzz workspace","entries":[],"notes":[],"version":"1.0"}',
    b"4096",
)


def minimize_failure(
    data: bytes,
    root: Path,
    surface: str,
    category: str | None = None,
    max_attempts: int = 256,
) -> bytes:
    """Deletion-minimize while preserving the failing surface and category."""

    candidate = data
    chunk = max(1, len(candidate) // 2)
    attempts = 0
    while candidate and chunk and attempts < max_attempts:
        changed = False
        for start in range(0, len(candidate), chunk):
            if attempts >= max_attempts:
                break
            trial = candidate[:start] + candidate[start + chunk :]
            attempts += 1
            try:
                check_surfaces(trial, root)
            except SurfaceInvariantError as error:
                if error.surface == surface and (
                    category is None or error.category == category
                ):
                    candidate = trial
                    changed = True
                    break
        if not changed:
            chunk //= 2
    return candidate


def _write_reproducer(
    artifacts: Path,
    data: bytes,
    error: SurfaceInvariantError,
    seed: int,
    iteration: int,
) -> None:
    digest = hashlib.sha256(data).hexdigest()
    stem = f"{error.surface}-{digest[:16]}"
    (artifacts / f"{stem}.bin").write_bytes(data)
    metadata = {
        "schema": "titan-fuzz-reproducer/1",
        "surface": error.surface,
        "category": error.category,
        "detail": error.detail,
        "seed": seed,
        "iteration": iteration,
        "sha256": digest,
        "size": len(data),
    }
    (artifacts / f"{stem}.json").write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def run(seconds: float, seed: int, artifacts: Path) -> int:
    rng = random.Random(seed)
    corpus = [*load_corpus(), *STRUCTURED_SEEDS]
    artifacts.mkdir(parents=True, exist_ok=True)
    deadline = time.monotonic() + seconds
    started = time.monotonic()
    iterations = 0
    hashes: set[str] = set()
    violations: Counter[str] = Counter()

    with TemporaryDirectory(prefix="titan-surface-fuzz-") as temporary:
        scratch = Path(temporary)
        pending = list(corpus)
        while pending or time.monotonic() < deadline:
            data = (
                pending.pop(0)
                if pending
                else mutate(
                    rng, rng.choice(corpus) if corpus and rng.random() < 0.5 else b""
                )
            )
            iterations += 1
            hashes.add(hashlib.sha256(data).hexdigest())
            try:
                check_surfaces(data, scratch)
            except SurfaceInvariantError as error:
                violations[f"{error.surface}:{error.category}"] += 1
                minimized = minimize_failure(
                    data, scratch, error.surface, category=error.category
                )
                _write_reproducer(
                    artifacts, minimized, error, seed=seed, iteration=iterations
                )
                print(f"FUZZ VIOLATION: {error}", file=sys.stderr)
                break

    summary = {
        "schema": "titan-fuzz-campaign/1",
        "seed": seed,
        "requested_seconds": seconds,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "corpus_seed_count": len(corpus),
        "iterations": iterations,
        "unique_input_hashes": len(hashes),
        "surfaces": list(SURFACES),
        "violations": dict(sorted(violations.items())),
    }
    (artifacts / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(
        f"surface fuzz: {iterations} iterations, {len(hashes)} unique inputs, "
        f"{sum(violations.values())} violations across {len(SURFACES)} surfaces"
    )
    return 1 if violations else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seconds", type=float, default=20.0)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--artifacts", type=Path, default=Path(".fuzz-artifacts"))
    args = parser.parse_args()
    return run(args.seconds, args.seed, args.artifacts)


if __name__ == "__main__":
    raise SystemExit(main())
