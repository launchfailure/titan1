"""Regression tests for rule-pack ReDoS mitigation.

A catastrophic-backtracking pattern supplied by a rule pack, evaluated against a
triggering payload, must be bounded by the hard timeout instead of hanging.
"""

import time

from titan_decoder.core import rule_packs
from titan_decoder.core.rule_packs import content_regex_search, evaluate_pack_rule


# A classic exponential-backtracking pattern; the payload of many 'a's with no
# trailing terminator forces the engine down the pathological path.
EVIL_PATTERN = r"(a+)+$"
TRIGGER = "a" * 40 + "!"


def test_catastrophic_pattern_is_bounded_by_timeout(monkeypatch):
    # Force the subprocess path (do not depend on re2 being installed here) and
    # use a short timeout to keep the test fast.
    start = time.monotonic()
    result = content_regex_search(EVIL_PATTERN, None, TRIGGER, timeout=1.0)
    elapsed = time.monotonic() - start
    # Bounded: without the guard this would run for many seconds/minutes.
    assert elapsed < 5.0
    # On timeout the rule is treated as "no match".
    assert result is False


def test_safe_pattern_still_matches():
    assert (
        content_regex_search(r"powershell", ["IGNORECASE"], "PowerShell -enc") is True
    )
    assert content_regex_search(r"nomatch", None, "benign text") is False


def test_evaluate_pack_rule_uses_bounded_search():
    rule = {
        "id": "EVIL-001",
        "type": "content_regex",
        "pattern": EVIL_PATTERN,
    }
    report = {"nodes": [{"content_preview": TRIGGER}]}
    start = time.monotonic()
    fired = evaluate_pack_rule(rule, report, {})
    assert time.monotonic() - start < 5.0
    assert fired is False


def test_content_regex_timeout_constant_reasonable():
    assert 0 < rule_packs.CONTENT_REGEX_TIMEOUT_SECONDS <= 10
