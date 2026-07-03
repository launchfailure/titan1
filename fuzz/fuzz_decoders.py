#!/usr/bin/env python3
"""Standalone fuzzer for Titan decoders and analyzers.

Runs a time-bounded loop that feeds random and corpus-derived bytes to every
decoder and analyzer, enforcing the safety invariants in ``invariants.py``
(never raise, bounded output, bounded time). Designed for a small CI time
budget and for longer local runs.

Usage:
    python fuzz/fuzz_decoders.py [--seconds N] [--seed S]

If Atheris (libFuzzer for Python) is installed, ``atheris_target`` can be wired
into a coverage-guided run; the default here is a portable random loop so it
runs anywhere without native dependencies.
"""

from __future__ import annotations

import argparse
import os
import random
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fuzz.invariants import check_all, InvariantError  # noqa: E402

CORPUS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "corpus")


def load_corpus() -> list:
    seeds = []
    if os.path.isdir(CORPUS_DIR):
        for name in sorted(os.listdir(CORPUS_DIR)):
            path = os.path.join(CORPUS_DIR, name)
            if os.path.isfile(path):
                try:
                    seeds.append(open(path, "rb").read())
                except OSError:
                    pass
    return seeds


def mutate(rng: random.Random, base: bytes) -> bytes:
    """Cheap mutations: flip bytes, truncate, extend, splice."""
    if not base or rng.random() < 0.15:
        return bytes(rng.randrange(256) for _ in range(rng.randint(0, 1024)))
    data = bytearray(base)
    for _ in range(rng.randint(1, 8)):
        op = rng.random()
        if op < 0.4 and data:
            data[rng.randrange(len(data))] = rng.randrange(256)
        elif op < 0.6 and data:
            del data[rng.randrange(len(data))]
        elif op < 0.8:
            data.insert(rng.randrange(len(data) + 1), rng.randrange(256))
        else:
            data.extend(bytes(rng.randrange(256) for _ in range(rng.randint(0, 64))))
    return bytes(data)


def run(seconds: float, seed: int) -> int:
    rng = random.Random(seed)
    corpus = load_corpus()
    deadline = time.monotonic() + seconds
    iterations = 0
    failures = 0

    # Always exercise the checked-in corpus first.
    for seed_bytes in corpus:
        iterations += 1
        try:
            check_all(seed_bytes)
        except InvariantError as e:
            failures += 1
            print(f"INVARIANT VIOLATION on corpus input: {e}", file=sys.stderr)

    while time.monotonic() < deadline:
        base = rng.choice(corpus) if corpus and rng.random() < 0.5 else b""
        data = mutate(rng, base)
        iterations += 1
        try:
            check_all(data)
        except InvariantError as e:
            failures += 1
            print(
                f"INVARIANT VIOLATION (len={len(data)}): {e}\n  repr={data[:64]!r}",
                file=sys.stderr,
            )

    print(f"fuzz: {iterations} iterations, {failures} violations")
    return 1 if failures else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--seconds", type=float, default=20.0, help="Time budget (default: 20s)"
    )
    parser.add_argument("--seed", type=int, default=0, help="RNG seed")
    args = parser.parse_args()
    return run(args.seconds, args.seed)


if __name__ == "__main__":
    raise SystemExit(main())
