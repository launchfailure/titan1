"""Golden-corpus differential tests + proven reproducibility.

Every checked-in golden input is re-analyzed and its normalized report compared,
byte-for-byte, against the stored expected report. A change in *analysis
output* — not just a crash — shows up here as a reviewable diff and cannot be
merged silently.

Reproducibility (M3.12): the same input and version must produce a byte-
identical normalized report across repeated runs (and, in CI, across the whole
Python matrix — the normalization strips the interpreter/platform fields).
"""

import os
import sys

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from tools.golden import (  # noqa: E402
    build_inputs,
    normalized_json,
    EXPECTED_DIR,
)
from titan_decoder.core.engine import TitanEngine  # noqa: E402
from titan_decoder.config import Config  # noqa: E402

_INPUTS = build_inputs()


@pytest.mark.parametrize("name", sorted(_INPUTS.keys()))
def test_output_matches_golden(name):
    data = _INPUTS[name]
    expected_path = os.path.join(EXPECTED_DIR, name + ".json")
    assert os.path.exists(expected_path), (
        f"missing golden for {name} (run tools/golden.py --regen)"
    )
    expected = open(expected_path).read()
    actual = normalized_json(TitanEngine(Config()).run_analysis(data))
    assert actual == expected, (
        f"Analysis output for {name} changed. If intentional, regenerate with "
        f"`python tools/golden.py --regen` and review the diff."
    )


@pytest.mark.parametrize("name", sorted(_INPUTS.keys()))
def test_reproducible_across_runs(name):
    data = _INPUTS[name]
    first = normalized_json(TitanEngine(Config()).run_analysis(data))
    second = normalized_json(TitanEngine(Config()).run_analysis(data))
    # Same input + same version => byte-identical normalized report.
    assert first == second


def test_reproducible_reusing_one_engine():
    # Reusing an engine (as batch mode does) must not change results: per-run
    # state is fully reset each run_analysis call.
    data = _INPUTS["nested_base64.txt"]
    engine = TitanEngine(Config())
    a = normalized_json(engine.run_analysis(data))
    _ = engine.run_analysis(_INPUTS["cfb_macro.doc"])  # interleave a different input
    b = normalized_json(engine.run_analysis(data))
    assert a == b


def test_goldens_are_checked_in():
    assert os.path.isdir(EXPECTED_DIR)
    assert len(os.listdir(EXPECTED_DIR)) >= len(_INPUTS)
