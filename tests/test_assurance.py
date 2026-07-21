import json
from dataclasses import dataclass
from pathlib import Path

import pytest

from titan_decoder.config import Config
from titan_decoder.cli import attach_assurance_stage
from titan_decoder.core.assurance import AssuranceEngine
from titan_decoder.core.case_report import build_case_report, to_html, to_markdown
from titan_decoder.core.engine import TitanEngine
from titan_decoder.workbench_ui.models import AnalysisSnapshot
from titan_decoder.workbench_ui.presenters import findings_text, summary_text
from titan_decoder.workbench_ui.services import WorkbenchServices


ROOT = Path(__file__).resolve().parents[1]


def _analyzed_text():
    return TitanEngine(Config()).run_analysis(
        b"This is a normal readable sentence with spaces and punctuation."
    )


def _root_hash(report):
    return next(node["sha256"] for node in report["nodes"] if node["parent"] is None)


def _trust_hash(tmp_path, digest):
    path = tmp_path / "trusted-hashes.txt"
    path.write_text(f"{digest} test fixture\n", encoding="utf-8")
    return path


def test_incomplete_payload_is_indeterminate_even_after_static_checks(tmp_path):
    report = TitanEngine(Config()).run_analysis(b"\x00" * 256)
    assurance = AssuranceEngine(
        {"trusted_hashes_path": str(_trust_hash(tmp_path, _root_hash(report)))}
    )

    assurance.run_static_checks(report)
    result = assurance.evaluate(report)

    assert result["verdict"] == "INDETERMINATE"
    states = {item["id"]: item["state"] for item in result["controls"]}
    assert states["complete_decoding"] == "fail"
    assert states["format_validation"] == "fail"
    assert states["no_opaque_payloads"] == "fail"
    assert states["static_analysis"] == "pass"
    assert states["dynamic_vm_analysis"] == "not_applicable"
    assert states["trusted_provenance"] == "pass"


def test_all_applicable_controls_can_reach_no_malicious_evidence(tmp_path):
    report = _analyzed_text()
    assurance = AssuranceEngine(
        {"trusted_hashes_path": str(_trust_hash(tmp_path, _root_hash(report)))}
    )

    assurance.run_static_checks(report)
    result = assurance.evaluate(report)

    assert result["verdict"] == "NO_MALICIOUS_EVIDENCE"
    assert result["all_required_controls_passed"] is True
    assert result["controls_satisfied"] == 6
    assert "not a guarantee" in result["summary"]


def test_executable_content_requires_hash_bound_vm_attestation(tmp_path):
    report = _analyzed_text()
    report["nodes"][0]["method"] = "ANALYZE_PE"
    digest = _root_hash(report)
    assurance = AssuranceEngine(
        {"trusted_hashes_path": str(_trust_hash(tmp_path, digest))}
    )
    assurance.run_static_checks(report)

    result = assurance.evaluate(report)

    assert result["verdict"] == "INDETERMINATE"
    dynamic = next(
        item for item in result["controls"] if item["id"] == "dynamic_vm_analysis"
    )
    assert dynamic["state"] == "unavailable"


def test_clean_vm_attestation_satisfies_executable_control(tmp_path):
    report = _analyzed_text()
    report["nodes"][0]["method"] = "ANALYZE_PE"
    digest = _root_hash(report)
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    (sandbox / f"{digest}.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "sample_sha256": digest,
                "completed": True,
                "isolation": "vm",
                "verdict": "no_malicious_behavior",
                "provider": "test-vm",
            }
        ),
        encoding="utf-8",
    )
    assurance = AssuranceEngine(
        {
            "trusted_hashes_path": str(_trust_hash(tmp_path, digest)),
            "sandbox_attestations_dir": str(sandbox),
        }
    )
    assurance.run_static_checks(report)

    result = assurance.evaluate(report)

    assert result["verdict"] == "NO_MALICIOUS_EVIDENCE"


def test_malicious_vm_attestation_overrides_missing_controls(tmp_path):
    report = _analyzed_text()
    report["nodes"][0]["method"] = "ANALYZE_ELF"
    digest = _root_hash(report)
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    (sandbox / f"{digest}.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "sample_sha256": digest,
                "completed": True,
                "isolation": "virtual_machine",
                "verdict": "malicious",
                "behaviors": ["credential theft"],
            }
        ),
        encoding="utf-8",
    )
    assurance = AssuranceEngine({"sandbox_attestations_dir": str(sandbox)})
    assurance.run_static_checks(report)

    result = assurance.evaluate(report)

    assert result["verdict"] == "MALICIOUS"
    assert result["confidence"] == 1.0


def test_mismatched_attestation_hash_is_rejected(tmp_path):
    report = _analyzed_text()
    report["nodes"][0]["method"] = "ANALYZE_PE"
    digest = _root_hash(report)
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    (sandbox / f"{digest}.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "sample_sha256": "0" * 64,
                "completed": True,
                "isolation": "vm",
                "verdict": "clean",
            }
        ),
        encoding="utf-8",
    )
    assurance = AssuranceEngine({"sandbox_attestations_dir": str(sandbox)})
    assurance.run_static_checks(report)

    result = assurance.evaluate(report)

    dynamic = next(
        item for item in result["controls"] if item["id"] == "dynamic_vm_analysis"
    )
    assert dynamic["state"] == "unavailable"


def test_hash_bound_provenance_attestation_can_satisfy_trust(tmp_path):
    report = _analyzed_text()
    digest = _root_hash(report)
    provenance = tmp_path / "provenance"
    provenance.mkdir()
    (provenance / f"{digest}.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "sample_sha256": digest,
                "trusted": True,
                "verification_method": "authenticode",
                "identity": "Fixture Publisher",
            }
        ),
        encoding="utf-8",
    )
    assurance = AssuranceEngine(
        {"provenance_attestations_dir": str(provenance)}
    )
    assurance.run_static_checks(report)

    result = assurance.evaluate(report)

    assert result["verdict"] == "NO_MALICIOUS_EVIDENCE"


def test_malicious_hash_match_is_a_confirmed_malicious_verdict(tmp_path):
    report = _analyzed_text()
    digest = _root_hash(report)
    malicious = tmp_path / "malicious-hashes.txt"
    malicious.write_text(f"{digest} confirmed fixture\n", encoding="utf-8")
    assurance = AssuranceEngine({"malicious_hashes_path": str(malicious)})
    assurance.run_static_checks(report)

    result = assurance.evaluate(report)

    assert result["verdict"] == "MALICIOUS"
    static = next(
        item for item in result["controls"] if item["id"] == "static_analysis"
    )
    assert static["disposition"] == "malicious"


def test_active_content_signal_prevents_benign_style_verdict(tmp_path):
    report = TitanEngine(Config()).run_analysis(
        b"powershell -NoProfile -Command Invoke-Expression payload"
    )
    assurance = AssuranceEngine(
        {"trusted_hashes_path": str(_trust_hash(tmp_path, _root_hash(report)))}
    )
    assurance.run_static_checks(report)

    result = assurance.evaluate(report)

    assert result["verdict"] == "SUSPICIOUS"
    static = next(
        item for item in result["controls"] if item["id"] == "static_analysis"
    )
    assert static["state"] == "fail"


def test_requested_but_missing_yara_provider_fails_closed(tmp_path):
    report = _analyzed_text()
    digest = _root_hash(report)
    assurance = AssuranceEngine(
        {
            "enable_yara": True,
            "yara_rules_path": str(tmp_path / "missing.yar"),
            "trusted_hashes_path": str(_trust_hash(tmp_path, digest)),
        }
    )
    assurance.run_static_checks(report, [(0, b"ordinary text")])

    result = assurance.evaluate(report)

    assert result["verdict"] == "INDETERMINATE"
    static = next(
        item for item in result["controls"] if item["id"] == "static_analysis"
    )
    assert static["state"] == "unavailable"


def test_workbench_static_suite_extracts_bounded_strings(tmp_path):
    config = Config(tmp_path / "missing-config.json")
    snapshot = WorkbenchServices(config).analyze(
        b"ordinary marker-string-for-triage content", "sample.txt"
    )

    assert any("marker-string-for-triage" in item for item in snapshot.strings)
    assert snapshot.report["static_analysis"]["strings_extracted"] >= 1


def test_cli_assurance_static_checks_include_evidence_iocs(tmp_path):
    @dataclass
    class Indicator:
        indicator_type: str
        value: str

    @dataclass
    class Evidence:
        indicators: list[Indicator]

    config = Config(tmp_path / "missing-config.json")
    engine = TitanEngine(config)
    report = engine.run_analysis(b"This is an ordinary readable sentence.")
    evidence = Evidence(
        [Indicator("urls", "https://evidence-only.example.test/beacon")]
    )

    attach_assurance_stage(config, report, engine, evidence)

    codes = {
        item["code"] for item in report["intelligence"]["signals"]
    }
    assert "network_urls" in codes
    assert report["assurance"]["verdict"] == "SUSPICIOUS"


def test_workbench_attaches_assurance_and_presenters_explain_it(tmp_path):
    config = Config(tmp_path / "missing-config.json")
    services = WorkbenchServices(config)

    snapshot = services.analyze(bytes(range(256)), "opaque.bin")

    assert snapshot.assurance["verdict"] == "SUSPICIOUS"
    assert "SUSPICIOUS" in summary_text(snapshot)
    findings = findings_text(snapshot)
    assert "Assurance controls" in findings
    assert "Complete decoding" in findings
    assert "Assurance blockers" in findings


def test_snapshot_without_assurance_remains_backward_compatible():
    snapshot = AnalysisSnapshot(report={"nodes": [], "iocs": {}})
    assert snapshot.assurance == {}
    assert "NOT ASSESSED" in summary_text(snapshot)


def test_assurance_output_matches_primary_report_schema(tmp_path):
    jsonschema = pytest.importorskip("jsonschema")
    report = _analyzed_text()
    digest = _root_hash(report)
    engine = AssuranceEngine(
        {"trusted_hashes_path": str(_trust_hash(tmp_path, digest))}
    )
    engine.run_static_checks(report)
    report["assurance"] = engine.evaluate(report)
    schema = json.loads(
        (ROOT / "docs" / "report.schema.json").read_text(encoding="utf-8")
    )

    jsonschema.Draft202012Validator(schema).validate(report)


def test_case_reports_render_assurance_and_escape_html(tmp_path):
    report = _analyzed_text()
    digest = _root_hash(report)
    engine = AssuranceEngine(
        {"trusted_hashes_path": str(_trust_hash(tmp_path, digest))}
    )
    engine.run_static_checks(report)
    report["assurance"] = engine.evaluate(report)
    case = build_case_report(report, None, report["iocs"])

    markdown = to_markdown(case)
    html = to_html(case)

    assert "## Assurance Verdict" in markdown
    assert "NO_MALICIOUS_EVIDENCE" in markdown
    assert "id='assurance'" in html

    case["assurance"]["summary"] = "<script>alert(1)</script>"
    escaped = to_html(case)
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in escaped
    assert "<script>alert(1)</script>" not in escaped
