from pathlib import Path


def test_cli_wires_threat_stage_before_enrichment():
    source = Path("titan_decoder/cli.py").read_text(encoding="utf-8")
    main_source = source[source.index("def main():"):]
    intelligence = main_source.index("attach_intelligence_stage(")
    threat = main_source.index("attach_threat_intelligence_stage(", intelligence)
    enrichment = main_source.index("run_enrichment_stage(", threat)
    assert intelligence < threat < enrichment


def test_graph_receives_threat_intelligence():
    source = Path("titan_decoder/cli.py").read_text(encoding="utf-8")
    assert 'threat_intelligence=report.get("threat_intelligence") or {}' in source
