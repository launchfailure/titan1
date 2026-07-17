"""Rule-pack hardening: duplicate-ID checks, validation, and limits.

Fixture packs live in tests/fixtures/rule_packs/. The same validation runs
in two places with different strictness: the engine skips bad rules with a
warning and keeps analyzing, while `--rules-validate` reports every problem
and exits non-zero.
"""

import json
from pathlib import Path

import pytest

from titan_decoder.core.detection_rules import CorrelationRulesEngine
from titan_decoder.core.rule_packs import (
    MAX_PATTERN_LENGTH,
    MAX_RULES_PER_PACK,
    RulePackError,
    load_rule_pack,
    validate_rule_def,
    validate_rule_pack,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "rule_packs"
VALID_PACK = FIXTURES / "valid-pack.json"
DUPLICATE_PACK = FIXTURES / "duplicate-ids.json"
INVALID_PACK = FIXTURES / "invalid-rules.json"


def _write_pack(tmp_path, rules, name="Generated Pack"):
    path = tmp_path / "pack.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "pack": {"name": name, "version": "0.0.1"},
                "rules": rules,
            }
        )
    )
    return path


# --- validate_rule_pack ----------------------------------------------------


def test_valid_fixture_pack_passes_validation():
    result = validate_rule_pack(VALID_PACK)
    assert result["ok"], result["errors"]
    assert result["errors"] == []
    assert result["name"] == "Fixture Valid Pack"
    assert result["rule_count"] == 2


def test_duplicate_ids_within_pack_fail_validation():
    result = validate_rule_pack(DUPLICATE_PACK)
    assert not result["ok"]
    assert any("duplicate rule id" in e for e in result["errors"])


@pytest.mark.parametrize(
    "label, fragment",
    [
        ("BAD-REGEX", "invalid regex pattern"),
        ("BAD-TYPE", "unknown rule type"),
        ("BAD-MISSING-PATTERN", "non-empty 'pattern'"),
        ("TITAN-001", "reserved for built-in rules"),
        ("BAD-ATTACK-IDS", "malformed attack_ids"),
        ("BAD-MIN-EACH", "'min_each' must be an integer"),
        ("BAD-FLAGS", "unknown flags"),
        ("BAD-SEVERITY", "unknown severity"),
    ],
)
def test_invalid_fixture_rules_each_report_their_problem(label, fragment):
    result = validate_rule_pack(INVALID_PACK)
    assert not result["ok"]
    assert any(e.startswith(f"{label}:") and fragment in e for e in result["errors"]), (
        label,
        result["errors"],
    )


def test_unreadable_pack_reports_load_error(tmp_path):
    missing = tmp_path / "nope.json"
    result = validate_rule_pack(missing)
    assert not result["ok"]
    assert result["errors"]


# --- limits ------------------------------------------------------------------


def test_pack_over_rule_limit_is_rejected_at_load(tmp_path):
    rules = [
        {"id": f"GEN-{i:04d}", "type": "content_regex", "pattern": "x"}
        for i in range(MAX_RULES_PER_PACK + 1)
    ]
    path = _write_pack(tmp_path, rules)
    with pytest.raises(RulePackError, match="exceeding the limit"):
        load_rule_pack(path)
    # The engine skips the whole pack (warning) instead of crashing.
    engine = CorrelationRulesEngine([path])
    assert engine.rule_packs == []
    assert all(rule.rule_id.startswith("TITAN-") for rule in engine.rules)


def test_pattern_over_length_limit_is_flagged():
    problems = validate_rule_def(
        {
            "id": "GEN-0001",
            "type": "content_regex",
            "pattern": "a" * (MAX_PATTERN_LENGTH + 1),
        }
    )
    assert any("exceeds" in p for p in problems)


def test_id_over_length_limit_is_flagged():
    problems = validate_rule_def(
        {"id": "X" * 65, "type": "content_regex", "pattern": "x"}
    )
    assert any("'id' exceeds" in p for p in problems)


# --- engine load-time enforcement -------------------------------------------


def test_engine_skips_duplicates_first_definition_wins(tmp_path):
    engine = CorrelationRulesEngine([DUPLICATE_PACK])
    dup_rules = [r for r in engine.rules if r.rule_id == "DUP-001"]
    assert len(dup_rules) == 1
    assert dup_rules[0].name == "First definition"
    meta = engine.rule_packs[0]
    assert meta["rules_loaded"] == 1
    assert meta["rules_skipped"] == 1


def test_engine_skips_cross_pack_duplicates(tmp_path):
    first = _write_pack(
        tmp_path,
        [{"id": "X-001", "type": "content_regex", "pattern": "first"}],
        name="First Pack",
    )
    second = tmp_path / "second.json"
    second.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "pack": {"name": "Second Pack", "version": "0.0.1"},
                "rules": [
                    {"id": "X-001", "type": "content_regex", "pattern": "second"}
                ],
            }
        )
    )
    engine = CorrelationRulesEngine([first, second])
    matches = [r for r in engine.rules if r.rule_id == "X-001"]
    assert len(matches) == 1
    assert matches[0].source["pack"] == "First Pack"
    assert engine.rule_packs[1]["rules_skipped"] == 1


def test_engine_rejects_builtin_id_impersonation_and_keeps_valid_rules():
    engine = CorrelationRulesEngine([INVALID_PACK])
    # The pack's TITAN-001 must not replace or duplicate the built-in.
    titan_001 = [r for r in engine.rules if r.rule_id == "TITAN-001"]
    assert len(titan_001) == 1
    assert (
        getattr(titan_001[0], "source", {"type": "builtin"}).get("type", "builtin")
        == "builtin"
    )
    # Every fixture rule is invalid, so none load.
    meta = engine.rule_packs[0]
    assert meta["rules_loaded"] == 0
    assert meta["rules_skipped"] == 8


def test_engine_loads_valid_rules_and_reports_counts():
    engine = CorrelationRulesEngine([VALID_PACK])
    meta = engine.rule_packs[0]
    assert meta["rules_loaded"] == 2
    assert meta["rules_skipped"] == 0
    report = {"nodes": [{"content_preview": "powershell iex downloadstring"}]}
    detections = engine.evaluate_all(report, {})
    assert any(d["rule_id"] == "FIX-001" for d in detections)
    fired = next(d for d in detections if d["rule_id"] == "FIX-001")
    assert fired["attack_ids"] == ["T1059.001", "T1105"]


# --- CLI --rules-validate ----------------------------------------------------


def _run_cli_validate(monkeypatch, capsys, *paths):
    from titan_decoder import cli

    argv = ["titan-decoder"]
    for p in paths:
        argv.extend(["--rules-validate", str(p)])
    monkeypatch.setattr("sys.argv", argv)
    try:
        cli.main()
        code = 0
    except SystemExit as e:
        code = e.code or 0
    return code, json.loads(capsys.readouterr().out)


def test_cli_rules_validate_passes_valid_pack(monkeypatch, capsys):
    code, payload = _run_cli_validate(monkeypatch, capsys, VALID_PACK)
    assert code == 0
    assert payload["ok"] is True
    assert payload["results"][0]["errors"] == []


def test_cli_rules_validate_fails_on_rule_problems(monkeypatch, capsys):
    code, payload = _run_cli_validate(monkeypatch, capsys, VALID_PACK, DUPLICATE_PACK)
    assert code == 1
    assert payload["ok"] is False
    by_path = {r["path"]: r for r in payload["results"]}
    assert by_path[str(VALID_PACK)]["ok"] is True
    assert any("duplicate rule id" in e for e in by_path[str(DUPLICATE_PACK)]["errors"])
