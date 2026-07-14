from pathlib import Path


def test_cli_wires_intelligence_before_enrichment():
    source = Path("titan_decoder/cli.py").read_text(encoding="utf-8")

    detection_call = "detections, risk_assessment = run_detections_stage("
    intelligence_call = "attach_intelligence_stage("
    enrichment_call = "run_enrichment_stage(args, config, report, evidence_result)"

    detection_index = source.index(detection_call)
    intelligence_index = source.index(intelligence_call, detection_index)
    enrichment_index = source.index(enrichment_call, intelligence_index)

    assert detection_index < intelligence_index < enrichment_index


def test_cli_contains_expected_milestone_stages():
    source = Path("titan_decoder/cli.py").read_text(encoding="utf-8")

    assert "run_detections_stage(" in source
    assert "attach_intelligence_stage(" in source
    assert "run_enrichment_stage(" in source
