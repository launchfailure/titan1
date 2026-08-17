"""Integration tests: SDK plugins running through the engine and CLI stages."""

import json
from pathlib import Path
from types import SimpleNamespace

from titan_decoder import cli
from titan_decoder.config import Config
from titan_decoder.core.case_report import build_case_report, to_html, to_markdown
from titan_decoder.core.engine import TitanEngine
from titan_decoder.plugins import PluginManager

EXAMPLES = Path(__file__).resolve().parents[1] / "examples" / "plugins"


def _args(**over):
    args = cli.build_parser().parse_args([])
    for key, value in over.items():
        setattr(args, key, value)
    return args


def test_engine_loads_manifest_plugins_from_config_dir():
    config = Config()
    config.set("plugin_dirs", [str(EXAMPLES)])
    engine = TitanEngine(config)
    decoder_names = {getattr(d, "name", "") for d in engine.decoders}
    analyzer_names = {getattr(a, "name", "") for a in engine.analyzers}
    assert "ROT47" in decoder_names
    assert "PrintableStrings" in analyzer_names
    info = engine.plugin_manager.get_plugin_info()
    assert {p["id"] for p in info["manifest_plugins"]} >= {
        "example.rot47",
        "example.strings",
        "example.marker",
        "example.config-extractor",
        "example.summary",
    }


def test_engine_decodes_with_sdk_decoder_plugin():
    """A DecodeResult-returning plugin decodes end to end inside the engine."""
    config = Config()
    config.set("plugin_dirs", [str(EXAMPLES / "rot47_decoder")])
    engine = TitanEngine(config)
    # ROT47-encoded text whose decode exposes a URL (clear structure gain):
    rot47 = bytes(
        ((b - 33 + 47) % 94) + 33 if 33 <= b <= 126 else b
        for b in b"fetch http://malware-marker.example/gate.php now"
    )
    report = engine.run_analysis(rot47)
    methods = {node.get("decoder_used") for node in report["nodes"]}
    assert "ROT47" in methods


def _manager():
    manager = PluginManager([EXAMPLES])
    manager.load_plugins()
    return manager


def test_detection_plugins_run_in_detection_stage():
    engine = SimpleNamespace(plugin_manager=_manager())
    report = {
        "meta": {"analysis_id": "t"},
        "node_count": 1,
        "nodes": [{"id": 0, "content_preview": "the MALWARE-MARKER is here"}],
        "iocs": {},
    }
    args = _args(enable_detections=True, quiet=True)
    detections, risk = cli.run_detections_stage(
        args, Config(), report, None, engine=engine
    )
    plugin_hits = [d for d in detections if d.get("source", {}).get("type") == "plugin"]
    assert len(plugin_hits) == 1
    hit = plugin_hits[0]
    assert hit["rule_id"] == "EXAMPLE-001"
    assert hit["severity"] == "medium"
    assert hit["source"]["plugin"] == "Example Marker"
    # Plugin findings persist in the report and feed risk scoring.
    assert hit in report["detections"]
    assert risk is not None


def test_config_extractor_runs_over_artifact_payloads():
    engine = TitanEngine(Config())
    engine.plugin_manager = _manager()
    engine.run_analysis(
        b"TITAN-BEACON|c2=https://c2.example/gate|campaign=red|key=001122"
    )
    report = {"meta": {}, "nodes": [], "iocs": {}}

    cli.run_config_extractors_stage(_args(quiet=True), Config(), report, engine)

    assert report["config_extractions"] == [
        {
            "family": "TitanBeacon",
            "confidence": 1.0,
            "values": {
                "c2": "https://c2.example/gate",
                "campaign": "red",
                "key": "001122",
            },
            "c2": ["https://c2.example/gate"],
            "keys": ["001122"],
            "campaign_id": "red",
            "metadata": {"format": "synthetic-example-v1"},
            "node_id": 0,
            "plugin": "Titan Beacon Config",
        }
    ]


def test_detection_plugin_failure_never_aborts_stage(tmp_path, capsys):
    plugin_dir = tmp_path / "crashy"
    plugin_dir.mkdir()
    (plugin_dir / "plugin.py").write_text(
        "from titan_decoder.plugins.api import DetectionPlugin\n"
        "class Crashy(DetectionPlugin):\n"
        "    name = 'Crashy'\n"
        "    rule_ids = ('CRASH-1',)\n"
        "    def detect(self, report, iocs, context=None):\n"
        "        raise RuntimeError('boom')\n"
    )
    (plugin_dir / "titan-plugin.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "id": "example.crashy",
                "name": "Crashy",
                "version": "1.0.0",
                "api_version": "1.1.0",
                "entry_point": "plugin:Crashy",
                "capabilities": ["detection"],
            }
        )
    )
    manager = PluginManager([tmp_path])
    manager.load_plugins()
    engine = SimpleNamespace(plugin_manager=manager)
    report = {"meta": {}, "node_count": 0, "nodes": [], "iocs": {}}
    args = _args(enable_detections=True, quiet=False)
    detections, _ = cli.run_detections_stage(
        args, Config(), report, None, engine=engine
    )
    assert all(d.get("source", {}).get("type") != "plugin" for d in detections)
    assert "Crashy failed" in capsys.readouterr().err


def test_report_plugins_contribute_sections_to_case_reports():
    engine = SimpleNamespace(plugin_manager=_manager())
    report = {"meta": {}, "node_count": 3, "nodes": [], "iocs": {}, "detections": []}
    cli._run_report_plugins(_args(quiet=True), Config(), report, engine)

    sections = report["plugin_report_sections"]
    assert len(sections) == 1
    section = sections[0]
    assert section["section_id"] == "example_summary"
    assert section["plugin"] == "Example Summary"
    assert section["content"]["node_count"] == 3

    case = build_case_report(report, None, {})
    markdown = to_markdown(case)
    assert "Example Plugin Summary" in markdown
    assert "Contributed by plugin: Example Summary" in markdown
    html = to_html(case)
    assert "Example Plugin Summary" in html


def test_cli_plugin_list_mode(capsys):
    args = _args(plugin_list=True, plugin_dir=[EXAMPLES])
    assert cli.handle_info_commands(args, Config()) == 0
    listing = json.loads(capsys.readouterr().out)
    assert listing["api_version"] == "1.2"
    assert {p["id"] for p in listing["manifest_plugins"]} >= {"example.rot47"}
    assert "ROT47" in listing["decoders"]


def test_cli_plugin_validate_mode(tmp_path, capsys):
    args = _args(plugin_validate=[EXAMPLES / "rot47_decoder"])
    assert cli.handle_info_commands(args, Config()) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["ok"] and output["results"][0]["ok"]

    broken = tmp_path / "broken"
    broken.mkdir()
    args = _args(plugin_validate=[broken])
    assert cli.handle_info_commands(args, Config()) == 1
    output = json.loads(capsys.readouterr().out)
    assert not output["ok"]


def test_cli_parser_plugin_defaults():
    args = cli.build_parser().parse_args(["--file", "x.bin"])
    assert args.plugin_dir is None
    assert args.plugin_validate is None
    assert args.plugin_list is False
