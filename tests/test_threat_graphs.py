import json

from titan_decoder.core.graph_export import GraphExporter


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
    "malware_tags": [],
    "relationships": [],
    "confidence": 0.9,
    "summary": "fixture",
}


def test_graph_json_contains_threat_annotations():
    nodes = [{"id": 1, "parent": None, "method": "ANALYZE"}]
    data = json.loads(GraphExporter(nodes, threat_intelligence=THREAT).to_json())
    assert data["metadata"]["threat_intelligence"]["technique_ids"] == ["T1059.001"]
    assert data["nodes"][0]["threat_intelligence"]["lolbins"] == ["powershell.exe"]


def test_dot_and_mermaid_include_threat_labels():
    nodes = [{"id": 1, "parent": None, "method": "ANALYZE"}]
    exporter = GraphExporter(nodes, threat_intelligence=THREAT)
    assert "T1059.001" in exporter.to_dot()
    assert "powershell.exe" in exporter.to_dot()
    assert "T1059.001" in exporter.to_mermaid()
