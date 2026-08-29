import json
from pathlib import Path

from titan_decoder.plugins.contracts import PLUGIN_API_VERSION
from titan_decoder.plugins.manifest import PluginManifest, validate_manifest
from titan_decoder.plugins.semver import is_manifest_api_compatible
from titan_decoder.workbench.models import TitanReport
from titan_decoder.workbench.workspace import (
    WORKSPACE_SCHEMA_VERSION,
    InvestigationWorkspace,
)

FIXTURES = Path(__file__).parent / "fixtures" / "compatibility"


def test_report_v1_reader_preserves_legacy_identity_lineage_and_risk():
    report = TitanReport.load(FIXTURES / "report-v1.0.json")

    assert report.summary.analysis_id == "legacy-case-001"
    assert report.summary.root_hash == "legacy-root-hash"
    assert report.summary.risk_level == "MEDIUM"
    assert report.summary.risk_score == 42.0
    assert report.node_by_id("child")["decoder_used"] == "Base64"
    assert [node["node_id"] for node in report.children_of("root")] == ["child"]


def test_workspace_v1_reader_upgrades_to_current_emitted_contract(tmp_path):
    workspace = InvestigationWorkspace.load(FIXTURES / "workspace-v1.0.json")

    assert workspace.name == "Legacy investigation"
    assert workspace.entries[0].tags == ["legacy", "reviewed"]
    assert workspace.entries[0].status == "closed"

    upgraded = tmp_path / "workspace.json"
    workspace.save(upgraded)
    emitted = json.loads(upgraded.read_text(encoding="utf-8"))
    assert emitted["schema_version"] == WORKSPACE_SCHEMA_VERSION
    assert emitted["entries"][0]["report_path"] == "legacy-report.json"


def test_plugin_manifest_v1_remains_compatible_with_current_api():
    manifest = PluginManifest.load(FIXTURES / "plugin-manifest-v1.0.json")

    assert validate_manifest(manifest) == ()
    assert is_manifest_api_compatible(manifest.api_version, PLUGIN_API_VERSION)
    assert manifest.to_dict()["schema_version"] == "1.0"
