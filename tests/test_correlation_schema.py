import pytest

from titan_decoder.correlation.models import CorrelationReport
from titan_decoder.correlation.schema import load_schema, validate_report_shape


def test_report_matches_json_schema():
    jsonschema = pytest.importorskip("jsonschema")
    report = CorrelationReport("case-a").to_dict()
    jsonschema.validate(report, load_schema())


def test_dependency_free_shape_validation():
    report = CorrelationReport("case-a").to_dict()
    assert validate_report_shape(report) == []


def test_schema_file_is_valid_json():
    assert load_schema()["title"] == "Titan Correlation Report v1.0"
