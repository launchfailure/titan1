"""The report schema is a versioned, guaranteed contract.

Every emitted report is validated against docs/report.schema.json. Downstream
tools depend on this shape, so these tests fail if the engine emits something
the schema does not allow — forcing a deliberate schema change (and version
bump) rather than a silent drift.
"""

import json
import os
import sys

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

jsonschema = pytest.importorskip("jsonschema")

from titan_decoder.core.engine import TitanEngine, SCHEMA_VERSION  # noqa: E402
from titan_decoder.config import Config  # noqa: E402

sys.path.insert(0, os.path.join(_ROOT, "tests"))
from _cfb_fixtures import build_cfb  # noqa: E402
from _pdf_fixtures import build_pdf, flate_stream  # noqa: E402

SCHEMA_PATH = os.path.join(_ROOT, "docs", "report.schema.json")


def _schema():
    with open(SCHEMA_PATH) as f:
        return json.load(f)


def _validator():
    schema = _schema()
    return jsonschema.Draft202012Validator(schema)


def _sample_inputs():
    return {
        "plain_text": b"just some text with http://example.com/ and 8.8.8.8",
        "nested_base64": __import__("base64").b64encode(
            __import__("base64").b64encode(b"http://c2.example/panel more bytes here")
        ),
        "cfb_doc": build_cfb([("Macros/VBA/Module1", b'Sub x()\nEnd Sub\n')]),
        "pdf": build_pdf(
            [(1, b"<< /Type /Catalog >>"), (2, flate_stream(b"", b"hello http://x.example/"))]
        ),
        "high_entropy": bytes((i * 37 + 11) % 256 for i in range(2048)),
    }


@pytest.mark.parametrize("name,data", list(_sample_inputs().items()))
def test_emitted_report_matches_schema(name, data):
    engine = TitanEngine(Config())
    report = engine.run_analysis(data)
    _validator().validate(report)


def test_report_with_detections_matches_schema():
    from titan_decoder.core.detection_rules import CorrelationRulesEngine
    from titan_decoder.core.risk_scoring import RiskScoringEngine
    from titan_decoder.core.ioc_export import build_ioc_summary

    engine = TitanEngine(Config())
    report = engine.run_analysis(
        b"powershell -enc http://evil.example/c2\n203.0.113.8\nadmin@evil.example\n"
    )
    rules = CorrelationRulesEngine()
    iocs = build_ioc_summary(report, None)
    report["detections"] = rules.evaluate_all(report, iocs)
    report["risk_assessment"] = RiskScoringEngine().compute_risk_score(
        report, iocs, report["detections"]
    )
    _validator().validate(report)


def test_every_node_has_provenance():
    engine = TitanEngine(Config())
    report = engine.run_analysis(
        __import__("base64").b64encode(b"http://c2.example/needs enough bytes here")
    )
    for node in report["nodes"]:
        assert node.get("provenance") is not None
        prov = node["provenance"]
        assert "origin" in prov and "reason" in prov
        if node["parent"] is None:
            assert prov["origin"] == "input"
        else:
            assert prov["parent_id"] == node["parent"]
            assert prov["parent_sha256"] is not None


def test_schema_const_matches_code_version():
    schema = _schema()
    meta_const = schema["properties"]["meta"]["properties"]["schema_version"]["const"]
    manifest_const = schema["properties"]["run_manifest"]["properties"]["tool"][
        "properties"
    ]["schema_version"]["const"]
    # A schema change must bump SCHEMA_VERSION in lockstep — this guards against
    # editing the schema without a version bump (and vice versa).
    assert meta_const == SCHEMA_VERSION
    assert manifest_const == SCHEMA_VERSION
