"""Regression test: numeric coercion must not crash on non-finite floats.

json.loads accepts Infinity/NaN by default, so an evidence JSONL field like
``"src_port": Infinity`` produced a float('inf'); _as_int then did a bare
int(inf) -> OverflowError (and int(nan) -> ValueError). That aborted
parse_evidence_file, and the CLI's catch-all then silently dropped ALL evidence
(warning only under --verbose), defeating the per-row resilience.
"""

import json

import pytest

from titan_decoder.core.evidence_parsers import _as_int, parse_evidence_file


@pytest.mark.parametrize(
    "value,expected",
    [
        (float("inf"), None),
        (float("-inf"), None),
        (float("nan"), None),
        (3.9, 3),
        ("inf", None),
        ("nan", None),
        ("12.5", 12),
        ("", None),
        ("abc", None),
        (None, None),
        (42, 42),
    ],
)
def test_as_int_handles_non_finite_and_junk(value, expected):
    assert _as_int(value) == expected


def test_firewall_jsonl_with_infinity_does_not_crash(tmp_path):
    p = tmp_path / "fw.jsonl"
    # Infinity / NaN are valid to json.loads by default.
    p.write_text(
        '{"timestamp":"2021-01-01T00:00:00Z","src_ip":"1.2.3.4","dst_ip":"5.6.7.8",'
        '"src_port":Infinity,"dst_port":NaN,"proto":"tcp","action":"allow"}\n'
    )
    res = parse_evidence_file(p, "firewall")
    # The record is kept (ports simply coerce to None) instead of the whole
    # file being discarded.
    assert len(res.events) == 1
    ev = res.events[0]
    raw = ev.to_dict()
    assert raw.get("src_ip") == "1.2.3.4"
    # Output must be JSON-serializable (no lingering inf/nan in numeric fields).
    json.dumps(raw)
