"""Performance regression guard tied to the committed baseline.

The deterministic part of the benchmark — the per-input node counts — is checked
here in the normal test suite (it is reproducible and hardware-independent, so
it never flakes). The wall-clock regression gate lives in `tools/bench.py
--check`, run as a dedicated CI step where a slow runner won't fail unrelated
tests; it is hardware-normalized against a calibration workload.
"""

import json
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from tools.bench import _bench_corpus, BASELINE_PATH  # noqa: E402
from titan_decoder.core.engine import TitanEngine  # noqa: E402
from titan_decoder.config import Config  # noqa: E402


def test_baseline_is_committed():
    assert os.path.exists(BASELINE_PATH), "run `python tools/bench.py --regen`"
    baseline = json.load(open(BASELINE_PATH))
    assert baseline["cases"], "baseline has no cases"
    assert baseline["calibration"] > 0


def test_node_counts_match_baseline():
    baseline = json.load(open(BASELINE_PATH))
    corpus = _bench_corpus()
    for name, data in corpus.items():
        assert name in baseline["cases"], f"{name} missing from baseline"
        report = TitanEngine(Config()).run_analysis(data)
        expected = baseline["cases"][name]["node_count"]
        assert report["node_count"] == expected, (
            f"{name}: node_count {report['node_count']} != baseline {expected}. "
            f"If intentional, regenerate with `python tools/bench.py --regen`."
        )
