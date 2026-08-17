"""Unit tests for the Plugin SDK v1: semver, manifest, registry, validation."""

import json
from pathlib import Path

import pytest

from titan_decoder.plugins import (
    AnalysisArtifact,
    ConfigExtraction,
    DecodeResult,
    DetectionFinding,
    PluginManager,
    PluginManifest,
    ReportSection,
    Version,
    is_manifest_api_compatible,
    satisfies,
    validate_manifest,
    validate_plugin,
)

EXAMPLES = Path(__file__).resolve().parents[1] / "examples" / "plugins"


# --- semver -----------------------------------------------------------------


def test_version_parse_and_shorthand():
    assert Version.parse("1.2.3") == Version(1, 2, 3)
    assert Version.parse("1.1") == Version(1, 1, 0)
    with pytest.raises(ValueError):
        Version.parse("not-a-version")
    with pytest.raises(ValueError):
        Version.parse("1.2.3.4")


def test_prerelease_precedence_follows_semver_spec():
    # SemVer 2.0.0 §11: pre-releases sort before the release, numeric
    # identifiers before alphanumeric.
    ordered = [
        Version.parse("1.0.0-alpha"),
        Version.parse("1.0.0-alpha.1"),
        Version.parse("1.0.0-alpha.beta"),
        Version.parse("1.0.0-beta"),
        Version.parse("1.0.0-beta.2"),
        Version.parse("1.0.0-beta.11"),
        Version.parse("1.0.0-rc.1"),
        Version.parse("1.0.0"),
    ]
    assert ordered == sorted(ordered)


def test_satisfies_requirement_forms():
    assert satisfies("1.5.0", "*")
    assert satisfies("1.5.0", "^1.0.0")
    assert not satisfies("2.0.0", "^1.0.0")
    assert satisfies("1.0.5", "~1.0.0")
    assert not satisfies("1.1.0", "~1.0.0")
    assert satisfies("1.5.0", ">=1.0.0,<2.0.0")
    assert not satisfies("2.5.0", ">=1.0.0,<2.0.0")
    assert satisfies("1.0.0", "1.0.0")
    with pytest.raises(ValueError):
        satisfies("1.0.0", "!!nonsense")


def test_manifest_api_compatibility():
    assert is_manifest_api_compatible("1.0.0", "1.1")
    assert is_manifest_api_compatible("1.1.0", "1.1")
    assert not is_manifest_api_compatible("1.2.0", "1.1")  # needs newer minor
    assert not is_manifest_api_compatible("2.0.0", "1.1")


# --- typed results ------------------------------------------------------------


def test_decode_result_unpacks_like_legacy_tuple():
    decoded, success = DecodeResult(b"data", True, {"k": "v"})
    assert decoded == b"data" and success is True
    with pytest.raises(TypeError):
        DecodeResult("not-bytes", True)


def test_analysis_artifact_unpacks_and_requires_basename():
    name, content = AnalysisArtifact("strings.txt", b"abc")
    assert name == "strings.txt" and content == b"abc"
    with pytest.raises(ValueError):
        AnalysisArtifact("../escape.txt", b"abc")


def test_detection_finding_validation():
    finding = DetectionFinding("X-1", "n", "d", "high", attack_ids=("T2", "T1", "T1"))
    assert finding.attack_ids == ("T1", "T2")
    with pytest.raises(ValueError):
        DetectionFinding("X-1", "n", "d", "catastrophic")


def test_config_extraction_validation_and_normalization():
    value = ConfigExtraction(
        "Example", 0.9, {"port": 443}, c2=("b.example", "a.example", "a.example")
    )
    assert value.c2 == ("a.example", "b.example")
    assert value.to_dict()["values"] == {"port": 443}
    with pytest.raises(ValueError):
        ConfigExtraction("", 0.5, {})
    with pytest.raises(ValueError):
        ConfigExtraction("Example", 1.1, {})


def test_report_section_validation():
    section = ReportSection("s", "t", {"a": 1}, formats=("markdown", "json"))
    assert section.formats == ("json", "markdown")
    with pytest.raises(ValueError):
        ReportSection("s", "t", {}, formats=("pdf",))


# --- manifest -----------------------------------------------------------------


def _manifest(**over):
    data = {
        "schema_version": "1.0",
        "id": "example.test",
        "name": "Example",
        "version": "1.0.0",
        "api_version": "1.0.0",
        "entry_point": "plugin:Example",
        "capabilities": ["decoder"],
    }
    data.update(over)
    return PluginManifest.from_dict(data)


def test_manifest_valid():
    assert validate_manifest(_manifest()) == ()


@pytest.mark.parametrize(
    "override,fragment",
    [
        ({"id": "Bad ID"}, "invalid plugin id"),
        ({"name": "  "}, "name must not be empty"),
        ({"version": "one"}, "invalid version"),
        ({"api_version": "9.0.0"}, "incompatible API version"),
        ({"entry_point": "no-colon"}, "entry_point"),
        ({"capabilities": []}, "capabilities must not be empty"),
        ({"capabilities": ["wizard"]}, "unsupported capabilities"),
        ({"permissions": ["root"]}, "unsupported permissions"),
        ({"dependencies": {"ok.dep": "!!bad"}}, "invalid dependency requirement"),
        ({"schema_version": "2.0"}, "unsupported schema_version"),
    ],
)
def test_manifest_invalid_fields(override, fragment):
    errors = validate_manifest(_manifest(**override))
    assert any(fragment in error for error in errors), errors


# --- registry -----------------------------------------------------------------


def _write_plugin(
    root,
    plugin_id,
    capability="detection",
    rule_ids=("EX-1",),
    version="1.0.0",
    dependencies=None,
    dirname=None,
):
    plugin_dir = root / (dirname or plugin_id.replace(".", "_"))
    plugin_dir.mkdir()
    body = {
        "detection": (
            "from titan_decoder.plugins.api import DetectionFinding, DetectionPlugin\n"
            "class Example(DetectionPlugin):\n"
            "    name = 'Example'\n"
            f"    rule_ids = {tuple(rule_ids)!r}\n"
            "    def detect(self, report, iocs, context=None):\n"
            "        return []\n"
        ),
        "decoder": (
            "from titan_decoder.plugins.api import DecoderPlugin\n"
            "class Example(DecoderPlugin):\n"
            "    name = 'ExampleDecoder'\n"
            "    def can_decode(self, data, context=None):\n"
            "        return False\n"
            "    def decode(self, data, context=None):\n"
            "        return data, False\n"
        ),
    }[capability]
    (plugin_dir / "plugin.py").write_text(body)
    (plugin_dir / "titan-plugin.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "id": plugin_id,
                "name": plugin_id,
                "version": version,
                "api_version": "1.1.0",
                "entry_point": "plugin:Example",
                "capabilities": [capability],
                "dependencies": dependencies or {},
            }
        )
    )
    return plugin_dir


def test_registry_loads_all_example_plugins():
    manager = PluginManager([EXAMPLES])
    manager.load_plugins()
    assert len(manager.manifest_plugins) == 7
    assert [d.name for d in manager.decoders] == ["ROT47"]
    assert [a.name for a in manager.analyzers] == ["PrintableStrings"]
    assert [d.name for d in manager.detections] == ["Example Marker"]
    assert {e.name for e in manager.extractors} == {
        "Cobalt Strike Beacon Config",
        "Remcos Config",
        "Titan Beacon Config",
    }
    assert [r.name for r in manager.reports] == ["Example Summary"]
    assert manager.errors == []


def test_registry_mixes_single_file_and_manifest_plugins(tmp_path):
    (tmp_path / "legacy.py").write_text(
        "from titan_decoder.plugins.api import PluginDecoder\n"
        "class Legacy(PluginDecoder):\n"
        "    name = 'LegacyDecoder'\n"
        "    def can_decode(self, data):\n"
        "        return False\n"
        "    def decode(self, data):\n"
        "        return data, False\n"
    )
    _write_plugin(tmp_path, "example.modern", capability="decoder")
    manager = PluginManager([tmp_path])
    manager.load_plugins()
    names = [d.name for d in manager.decoders]
    assert "LegacyDecoder" in names and "ExampleDecoder" in names


def test_registry_resolves_dependencies_regardless_of_directory_order(tmp_path):
    # "aaa_consumer" sorts before "zzz_base": naive name-order loading would
    # fail the dependency check.
    _write_plugin(tmp_path, "example.base", capability="decoder", dirname="zzz_base")
    _write_plugin(
        tmp_path,
        "example.consumer",
        rule_ids=("EX-CONSUMER-1",),
        dependencies={"example.base": "^1.0.0"},
        dirname="aaa_consumer",
    )
    manager = PluginManager([tmp_path])
    manager.load_plugins()
    assert set(manager.manifest_plugins) == {"example.base", "example.consumer"}
    assert manager.errors == []


def test_registry_rejects_unsatisfied_dependency(tmp_path):
    _write_plugin(tmp_path, "example.base", capability="decoder", version="0.9.0")
    _write_plugin(
        tmp_path,
        "example.consumer",
        dependencies={"example.base": "^1.0.0"},
    )
    manager = PluginManager([tmp_path])
    manager.load_plugins()
    assert "example.consumer" not in manager.manifest_plugins
    assert any("does not satisfy" in error["error"] for error in manager.errors)


def test_registry_rejects_reserved_and_duplicate_rule_ids(tmp_path):
    _write_plugin(tmp_path, "example.reserved", rule_ids=("TITAN-999",))
    _write_plugin(tmp_path, "example.first", rule_ids=("SHARED-1",), dirname="m_first")
    _write_plugin(
        tmp_path, "example.second", rule_ids=("SHARED-1",), dirname="n_second"
    )
    manager = PluginManager([tmp_path])
    manager.load_plugins()
    assert "example.reserved" not in manager.manifest_plugins
    assert "example.first" in manager.manifest_plugins
    assert "example.second" not in manager.manifest_plugins
    errors = " ".join(error["error"] for error in manager.errors)
    assert "reserved" in errors and "duplicate detection rule ids" in errors


def test_registry_rejects_duplicate_plugin_ids(tmp_path):
    _write_plugin(tmp_path, "example.dup", capability="decoder", dirname="one")
    _write_plugin(tmp_path, "example.dup", capability="decoder", dirname="two")
    manager = PluginManager([tmp_path])
    manager.load_plugins()
    assert len(manager.manifest_plugins) == 1
    assert any("duplicate plugin id" in error["error"] for error in manager.errors)


# --- validation ----------------------------------------------------------------


def test_validate_all_example_plugins():
    for path in sorted(EXAMPLES.iterdir()):
        report = validate_plugin(path)
        assert report.ok, (path, [issue.to_dict() for issue in report.issues])


def test_validate_missing_and_malformed_manifest(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    assert not validate_plugin(empty).ok

    bad = tmp_path / "bad"
    bad.mkdir()
    (bad / "titan-plugin.json").write_text("{not json")
    assert not validate_plugin(bad).ok

    invalid = tmp_path / "invalid"
    invalid.mkdir()
    (invalid / "titan-plugin.json").write_text(
        json.dumps(
            {
                "id": "Bad ID",
                "name": "",
                "version": "1.0.0",
                "api_version": "9.0.0",
                "entry_point": "bad",
                "capabilities": [],
            }
        )
    )
    report = validate_plugin(invalid)
    assert not report.ok
    assert all(issue.code.startswith("manifest.") for issue in report.issues)


def test_validate_capability_mismatch(tmp_path):
    plugin_dir = _write_plugin(tmp_path, "example.mismatch", capability="decoder")
    manifest = json.loads((plugin_dir / "titan-plugin.json").read_text())
    manifest["capabilities"] = ["report"]
    (plugin_dir / "titan-plugin.json").write_text(json.dumps(manifest))
    report = validate_plugin(plugin_dir)
    assert not report.ok
    assert any(
        issue.code == "entry_point.capability_mismatch" for issue in report.issues
    )


def test_validate_runtime_type_errors(tmp_path):
    plugin_dir = tmp_path / "badtypes"
    plugin_dir.mkdir()
    (plugin_dir / "plugin.py").write_text(
        "from titan_decoder.plugins.api import DecoderPlugin\n"
        "class Bad(DecoderPlugin):\n"
        "    name = 'Bad'\n"
        "    def can_decode(self, data, context=None):\n"
        "        return 'yes'\n"
        "    def decode(self, data, context=None):\n"
        "        return 'not-bytes'\n"
    )
    (plugin_dir / "titan-plugin.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "id": "example.badtypes",
                "name": "Bad Types",
                "version": "1.0.0",
                "api_version": "1.1.0",
                "entry_point": "plugin:Bad",
                "capabilities": ["decoder"],
            }
        )
    )
    report = validate_plugin(plugin_dir)
    assert not report.ok
    codes = {issue.code for issue in report.issues}
    assert "decoder.can_decode_type" in codes and "decoder.result_type" in codes


def test_validate_undeclared_detection_rule(tmp_path):
    plugin_dir = tmp_path / "undeclared"
    plugin_dir.mkdir()
    (plugin_dir / "plugin.py").write_text(
        "from titan_decoder.plugins.api import DetectionFinding, DetectionPlugin\n"
        "class Sneaky(DetectionPlugin):\n"
        "    name = 'Sneaky'\n"
        "    rule_ids = ('DECLARED-1',)\n"
        "    def detect(self, report, iocs, context=None):\n"
        "        return [DetectionFinding('OTHER-1', 'n', 'd', 'low')]\n"
    )
    (plugin_dir / "titan-plugin.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "id": "example.sneaky",
                "name": "Sneaky",
                "version": "1.0.0",
                "api_version": "1.1.0",
                "entry_point": "plugin:Sneaky",
                "capabilities": ["detection"],
            }
        )
    )
    report = validate_plugin(plugin_dir)
    assert not report.ok
    assert any(issue.code == "detection.undeclared_rule" for issue in report.issues)


def test_manifest_matches_json_schema():
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(
        (
            Path(__file__).resolve().parents[1]
            / "schemas"
            / "titan-plugin-manifest-v1.0.schema.json"
        ).read_text()
    )
    for path in sorted(EXAMPLES.iterdir()):
        manifest = json.loads((path / "titan-plugin.json").read_text())
        jsonschema.validate(manifest, schema)
