from titan_decoder.core.case_report import (
    build_case_report,
    to_html,
    to_markdown,
)


THREAT = {
    "version": "1.0",
    "catalog_version": "fixture",
    "techniques": [
        {
            "technique_id": "T1059.001",
            "name": "PowerShell",
            "tactics": ["execution"],
            "confidence": 0.9,
            "evidence": [{"kind": "node", "node_id": 1}],
            "source_rules": ["fixture"],
        }
    ],
    "tactics": ["execution"],
    "lolbins": [
        {
            "name": "PowerShell",
            "executable": "powershell.exe",
            "technique_ids": ["T1059.001"],
            "confidence": 0.9,
            "node_ids": [1],
            "matched_terms": ["-enc"],
        }
    ],
    "malware_tags": [
        {
            "tag": "script-stager-like",
            "category": "execution",
            "confidence": 0.8,
            "reasons": ["encoded script"],
            "node_ids": [1],
        }
    ],
    "relationships": [],
    "confidence": 0.9,
    "summary": "fixture",
}


def test_case_report_renders_threat_intelligence():
    case = build_case_report(
        {"meta": {}, "node_count": 1, "threat_intelligence": THREAT},
        None,
        {},
    )
    markdown = to_markdown(case)
    html = to_html(case)
    assert "## Threat Intelligence" in markdown
    assert "T1059.001" in markdown
    assert "powershell.exe" in markdown
    assert "script-stager-like" in markdown
    assert "id='threat-intelligence'" in html
