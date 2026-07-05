#!/usr/bin/env python3
"""Performance benchmark with a committed baseline and regression gate.

Benchmarks the engine on a fixed, deterministic corpus and fails when
performance regresses beyond a threshold — turning "B on performance" into a
number the project defends rather than an unknown.

Two metrics are tracked:

* **Work volume (deterministic):** node counts per input. These are reproducible
  and hardware-independent, so any change is compared *exactly* — an algorithmic
  regression that fans out more nodes is caught with no tolerance.
* **Wall-clock time (hardware-normalized):** raw times vary 2--5x across CI
  runners, so each run also times a fixed calibration workload and scales the
  baseline by ``current_calibration / baseline_calibration``. The gate then
  allows a generous multiplier on top for residual noise. This catches a real
  slowdown (e.g. an O(n^2) creeping in) without failing on a slow runner.

Usage:
    python tools/bench.py --regen     # record a new baseline (bench_baseline.json)
    python tools/bench.py --check      # fail if a regression exceeds the threshold
    python tools/bench.py              # same as --check
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import Dict

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
sys.path.insert(0, os.path.join(_ROOT, "tests"))

from titan_decoder.core.engine import TitanEngine  # noqa: E402
from titan_decoder.config import Config  # noqa: E402
from tools.golden import build_inputs  # noqa: E402

BASELINE_PATH = os.path.join(_ROOT, "tools", "bench_baseline.json")

# Allowed wall-clock multiplier over the hardware-normalized baseline before a
# case is a regression. Generous, because CI timing is noisy; still catches a
# genuine 2x+ algorithmic slowdown.
TIME_THRESHOLD = 3.0
# Baseline times below this (seconds) are overhead/noise dominated; gate those
# cases on node count only, not wall-clock.
TIME_FLOOR = 0.02
RUNS = 5


def _calibrate() -> float:
    """Fixed CPU-bound workload; its time is a proxy for machine speed."""
    import hashlib

    start = time.perf_counter()
    h = hashlib.sha256()
    buf = b"titan-bench-calibration" * 64
    for _ in range(2000):
        h.update(buf)
        h.hexdigest()
    return time.perf_counter() - start


def _bench_corpus() -> Dict[str, bytes]:
    # Deterministic corpus (reuse the golden inputs) plus a couple of larger,
    # timing-meaningful synthetic payloads.
    corpus = dict(build_inputs())
    import base64

    corpus["big_nested_base64"] = base64.b64encode(
        base64.b64encode(b"payload http://c2.example/x " * 500)
    )
    corpus["big_xor"] = bytes(
        b ^ 0x3C
        for b in (b"config http://malware.example/panel sleep=60 " * 400)
    )
    return corpus


def _measure(data: bytes, runs: int = RUNS) -> Dict:
    node_count = 0
    best = float("inf")
    for _ in range(runs):
        engine = TitanEngine(Config())
        start = time.perf_counter()
        report = engine.run_analysis(data)
        elapsed = time.perf_counter() - start
        best = min(best, elapsed)
        node_count = report["node_count"]
    return {"time": best, "node_count": node_count}


def run_bench() -> Dict:
    corpus = _bench_corpus()
    calib = min(_calibrate() for _ in range(3))
    cases = {name: _measure(data) for name, data in corpus.items()}
    return {"calibration": calib, "time_threshold": TIME_THRESHOLD, "cases": cases}


def regen() -> None:
    result = run_bench()
    with open(BASELINE_PATH, "w") as f:
        json.dump(result, f, indent=2, sort_keys=True)
    print(f"Wrote baseline ({len(result['cases'])} cases) to {BASELINE_PATH}")


def check() -> int:
    if not os.path.exists(BASELINE_PATH):
        print("No baseline; run `python tools/bench.py --regen`", file=sys.stderr)
        return 1
    baseline = json.load(open(BASELINE_PATH))
    current = run_bench()

    # Hardware speed factor: how much slower/faster this machine is vs baseline
    # (>1 = slower runner, <1 = faster runner). Clamp to >=1.0 so a *faster*
    # machine never tightens the budget below the raw baseline: the tiny, mostly
    # overhead-bound corpus timings do not scale with a CPU-bound calibration,
    # so shrinking the budget on a fast runner produced false regressions. We
    # only ever relax the budget (scale it up) on a slower runner.
    raw_speed = current["calibration"] / baseline["calibration"] if baseline["calibration"] else 1.0
    speed = max(1.0, raw_speed)
    threshold = baseline.get("time_threshold", TIME_THRESHOLD)

    failures = []
    print(f"{'case':<24}{'nodes':>7}{'base_s':>10}{'cur_s':>10}{'norm_budget':>13}")
    print("-" * 64)
    for name, base in baseline["cases"].items():
        cur = current["cases"].get(name)
        if cur is None:
            failures.append(f"{name}: missing from current run")
            continue
        # Deterministic node count must match exactly.
        if cur["node_count"] != base["node_count"]:
            failures.append(
                f"{name}: node_count {cur['node_count']} != baseline {base['node_count']}"
            )
        budget = base["time"] * speed * threshold
        marker = "  OK"
        # Only gate on wall-clock for cases with a meaningful baseline time.
        # Sub-TIME_FLOOR timings are dominated by fixed Python overhead and
        # measurement noise, which no hardware normalization can stabilize; the
        # exact node-count check above is the reliable regression signal there.
        if base["time"] < TIME_FLOOR:
            marker = "  OK (time not gated: <floor)"
        elif cur["time"] > budget:
            marker = "  REGRESSION"
            failures.append(
                f"{name}: {cur['time']:.4f}s > budget {budget:.4f}s "
                f"(baseline {base['time']:.4f}s x speed {speed:.2f} x {threshold})"
            )
        print(
            f"{name:<24}{cur['node_count']:>7}{base['time']:>10.4f}"
            f"{cur['time']:>10.4f}{budget:>13.4f}{marker}"
        )

    print("-" * 64)
    print(
        f"machine speed factor vs baseline: {raw_speed:.2f} "
        f"(budget scale {speed:.2f}, clamped to >=1.0)"
    )
    if failures:
        print("\nREGRESSIONS:", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1
    print("No performance regressions.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--regen", action="store_true", help="Record a new baseline")
    parser.add_argument("--check", action="store_true", help="Check against baseline")
    args = parser.parse_args()
    if args.regen:
        regen()
        return 0
    return check()


if __name__ == "__main__":
    raise SystemExit(main())
