"""Tests for supply-chain artifacts: SBOM validity, determinism, and freshness.

The committed SBOM must be valid CycloneDX, deterministic (byte-reproducible for
the same version), and in sync with the generator — the release workflow diffs
it, so drift must fail here first.
"""

import json
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from tools.gen_sbom import build_sbom  # noqa: E402
from titan_decoder import __version__  # noqa: E402

SBOM_PATH = os.path.join(_ROOT, "docs", "sbom.cdx.json")


def test_sbom_is_valid_cyclonedx():
    sbom = build_sbom()
    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == "1.5"
    assert sbom["metadata"]["component"]["name"] == "titan-decoder"
    assert sbom["metadata"]["component"]["version"] == __version__
    for comp in sbom["components"]:
        assert comp["type"] == "library"
        assert comp["name"] and comp["purl"].startswith("pkg:pypi/")
    component_names = {component["name"].lower() for component in sbom["components"]}
    assert "textual" in component_names
    assert "google-re2" not in component_names


def test_sbom_is_deterministic():
    a = json.dumps(build_sbom(), sort_keys=True)
    b = json.dumps(build_sbom(), sort_keys=True)
    assert a == b
    # No wall-clock timestamp in the deterministic form.
    assert "timestamp" not in build_sbom()["metadata"]


def test_committed_sbom_matches_generator():
    assert os.path.exists(SBOM_PATH), "run `python tools/gen_sbom.py`"
    committed = open(SBOM_PATH).read()
    fresh = json.dumps(build_sbom(), indent=2, sort_keys=True) + "\n"
    assert committed == fresh, (
        "docs/sbom.cdx.json is stale — regenerate with `python tools/gen_sbom.py`"
    )


def test_detection_quality_history_present():
    hist = os.path.join(_ROOT, "docs", "detection_quality_history.jsonl")
    assert os.path.exists(hist)
    lines = [line for line in open(hist) if line.strip()]
    assert lines, "history should have at least one release entry"
    entry = json.loads(lines[-1])
    assert "version" in entry and "macro_precision" in entry
    assert entry["risk_separated"] is True
