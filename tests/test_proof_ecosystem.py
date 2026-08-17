import copy
import json
from pathlib import Path

import pytest

from titan_decoder.ecosystem.catalog import (
    compatible_plugins,
    load_catalog,
    validate_catalog,
)
from tools import publish_proof


ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "registry" / "plugins-v1.json"


def test_committed_catalog_is_valid_and_compatible():
    catalog = load_catalog(CATALOG)
    plugins = compatible_plugins(catalog, "1.1")
    assert [plugin["id"] for plugin in plugins] == ["example.rot47"]
    assert compatible_plugins(catalog, "2.0") == []


def test_catalog_rejects_mutable_or_untrusted_provenance():
    catalog = load_catalog(CATALOG)
    bad = copy.deepcopy(catalog)
    bad["plugins"][0]["source_url"] = "http://example.test/plugin"
    bad["plugins"][0]["source_commit"] = "main"
    errors = validate_catalog(bad)
    assert any("HTTPS" in error for error in errors)
    assert any("full Git commit" in error for error in errors)


def test_catalog_matches_published_json_schema():
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(
        (ROOT / "schemas" / "titan-plugin-catalog-v1.0.schema.json").read_text()
    )
    jsonschema.validate(load_catalog(CATALOG), schema)


def test_proof_bundle_is_current_and_audit_scope_is_honest():
    for path, payload in publish_proof.generated().items():
        assert path.read_bytes() == payload, f"regenerate {path.relative_to(ROOT)}"
    audit = json.loads(
        (ROOT / "docs" / "proof" / "parser-audit-scope.json").read_text()
    )
    assert audit["external_assessment"] == {
        "assessor": None,
        "report_url": None,
        "status": "ready-for-independent-review",
    }
    assert audit["source_files"]


def test_stix_export_includes_required_indicator_timestamps(tmp_path):
    from titan_decoder.core.ioc_export import export_stix_minimal

    output = tmp_path / "bundle.json"
    export_stix_minimal({"urls": ["https://example.test/a"]}, output)
    indicator = json.loads(output.read_text())["objects"][0]
    assert indicator["created"] == indicator["modified"] == indicator["valid_from"]
