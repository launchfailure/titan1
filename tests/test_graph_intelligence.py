import json

from titan_decoder.core.graph_export import GraphExporter


def _nodes():
    return [
        {
            "id": 0,
            "parent": None,
            "depth": 0,
            "method": "source",
            "content_type": "Text",
            "decoded_length": 80,
            "decode_score": 0.1,
            "decoder_used": None,
            "pruned": False,
        },
        {
            "id": 7,
            "parent": 0,
            "depth": 1,
            "method": "Base64",
            "content_type": "Text",
            "decoded_length": 42,
            "decode_score": 0.9,
            "decoder_used": "Base64",
            "pruned": False,
            "artifact_name": "decoded-script",
        },
    ]


def _intelligence():
    return {
        "version": "1.0",
        "intelligence_score": 62,
        "classification": "HIGH_RISK_PAYLOAD",
        "confidence": 0.62,
        "signals": [
            {"code": "execution_context", "points": 16, "summary": "Execution found"}
        ],
        "top_artifacts": [
            {
                "node_id": 7,
                "artifact_name": "decoded-script",
                "method": "Base64",
                "score": 65,
                "reasons": ["execution context", "network indicator"],
            }
        ],
        "recommendation": "High-priority manual review",
    }


def test_json_graph_includes_summary_and_node_annotation():
    payload = json.loads(GraphExporter(_nodes(), _intelligence()).to_json())

    assert payload["metadata"]["intelligence"]["classification"] == "HIGH_RISK_PAYLOAD"
    assert payload["metadata"]["intelligence"]["score"] == 62
    assert payload["metadata"]["intelligence"]["signal_codes"] == ["execution_context"]
    annotated = next(node for node in payload["nodes"] if node["id"] == 7)
    assert annotated["intelligence"]["rank"] == 1
    assert annotated["intelligence"]["priority"] == "high"
    assert annotated["intelligence"]["score"] == 65


def test_json_graph_without_intelligence_keeps_legacy_shape():
    payload = json.loads(GraphExporter(_nodes()).to_json())

    assert "intelligence" not in payload["metadata"]
    assert all("intelligence" not in node for node in payload["nodes"])


def test_dot_graph_has_summary_legend_and_highlighted_artifact():
    dot = GraphExporter(_nodes(), _intelligence()).to_dot()

    assert "Classification: HIGH_RISK_PAYLOAD" in dot
    assert "Intelligence: 62/100" in dot
    assert "cluster_titan_legend" in dot
    assert "Priority: HIGH (65/100)" in dot
    assert 'penwidth="2.5"' in dot


def test_mermaid_graph_has_summary_classes_and_priority_annotation():
    mermaid = GraphExporter(_nodes(), _intelligence()).to_mermaid()

    assert "intelligence_summary" in mermaid
    assert "HIGH_RISK_PAYLOAD · 62/100 · 62%" in mermaid
    assert "Priority: HIGH (65/100)" in mermaid
    assert "class node_7 titanHigh" in mermaid
    assert "classDef titanHigh" in mermaid


def test_missing_artifact_node_is_ignored():
    intelligence = _intelligence()
    intelligence["top_artifacts"] = [
        {
            "node_id": 999,
            "score": 100,
            "reasons": ["not in graph"],
        }
    ]

    payload = json.loads(GraphExporter(_nodes(), intelligence).to_json())

    assert payload["metadata"]["intelligence"]["annotated_node_count"] == 0
    assert all("intelligence" not in node for node in payload["nodes"])


def test_graph_text_is_escaped():
    nodes = _nodes()
    nodes[1]["method"] = 'bad "label" <tag>|pipe'
    exporter = GraphExporter(nodes, _intelligence())

    dot = exporter.to_dot()
    mermaid = exporter.to_mermaid()

    assert '\\"label\\"' in dot
    assert "&lt;tag&gt;/pipe" in mermaid
