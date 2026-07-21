from hashlib import sha256
from pathlib import Path
import sys

import pytest

from titan_decoder.core.assurance import AssuranceEngine
from titan_decoder.core.assurance_providers import AssuranceProviderRunner


def _report(data: bytes, *, active: bool = False) -> dict:
    return {
        "nodes": [
            {
                "id": 0,
                "parent": None,
                "sha256": sha256(data).hexdigest(),
                "method": "ANALYZE_PE" if active else "INPUT",
                "content_type": "Text",
                "content_preview": "MZ" if active else "ordinary text",
            }
        ],
        "analysis_outcome": {
            "complete": True,
            "status": "analyzed",
            "terminal_node_ids": [0],
            "opaque_terminal_node_ids": [],
            "limitations": [],
        },
        "static_analysis": {"completed": True, "yara": {"matches": []}},
        "detections": [],
        "intelligence": {"signals": []},
    }


def _provider_script(path: Path) -> None:
    path.write_text(
        """import json, sys
request = json.load(sys.stdin)
kind = request["provider_kind"]
if kind == "sandbox":
    result = {
        "schema_version": "1.0",
        "sample_sha256": request["sample_sha256"],
        "completed": True,
        "isolation": "vm",
        "verdict": "no_malicious_behavior",
        "provider": "test-vm",
    }
else:
    result = {
        "schema_version": "1.0",
        "sample_sha256": request["sample_sha256"],
        "trusted": True,
        "verification_method": "test-signature",
        "identity": "Titan Test Publisher",
    }
json.dump(result, sys.stdout)
""",
        encoding="utf-8",
    )


def test_provider_runner_writes_hash_bound_attestations(tmp_path):
    sample = tmp_path / "active.bin"
    sample.write_bytes(b"MZ test executable")
    provider = tmp_path / "provider.py"
    _provider_script(provider)
    sandbox = tmp_path / "sandbox"
    provenance = tmp_path / "provenance"
    config = {
        "sandbox_provider_command": [sys.executable, str(provider)],
        "provenance_provider_command": [sys.executable, str(provider)],
        "sandbox_attestations_dir": str(sandbox),
        "provenance_attestations_dir": str(provenance),
    }
    report = _report(sample.read_bytes(), active=True)

    statuses = AssuranceProviderRunner(config).collect(
        sample, report, allow_external=True
    )
    digest = sha256(sample.read_bytes()).hexdigest()

    assert [status["state"] for status in statuses] == ["completed", "completed"]
    assert (sandbox / f"{digest}.json").is_file()
    assert (provenance / f"{digest}.json").is_file()
    assurance = AssuranceEngine(config).evaluate(report)
    controls = {control["id"]: control for control in assurance["controls"]}
    assert controls["dynamic_vm_analysis"]["state"] == "pass"
    assert controls["trusted_provenance"]["state"] == "pass"


def test_provider_commands_are_disabled_offline(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"sample")
    report = _report(sample.read_bytes())
    statuses = AssuranceProviderRunner(
        {
            "sandbox_provider_command": ["not-invoked"],
            "sandbox_attestations_dir": str(tmp_path / "sandbox"),
        }
    ).collect(sample, report)

    assert statuses[0]["state"] == "unavailable"
    assert "offline mode" in statuses[0]["error"]


def test_provider_runner_rejects_report_path_hash_mismatch(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"sample")
    report = _report(b"different")

    with pytest.raises(ValueError, match="does not match"):
        AssuranceProviderRunner({}).collect(sample, report)


def test_provider_runner_rejects_string_commands(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"sample")
    report = _report(sample.read_bytes())
    statuses = AssuranceProviderRunner(
        {
            "sandbox_provider_command": "unsafe shell string",
            "sandbox_attestations_dir": str(tmp_path / "sandbox"),
        }
    ).collect(sample, report, allow_external=True)

    assert statuses[0]["state"] == "unavailable"
    assert "argv array" in statuses[0]["error"]


def test_provider_output_must_match_sample_hash(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"sample")
    provider = tmp_path / "bad-provider.py"
    provider.write_text(
        "import json; print(json.dumps({'schema_version':'1.0',"
        "'sample_sha256':'0'*64,'completed':True,'isolation':'vm',"
        "'verdict':'clean'}))",
        encoding="utf-8",
    )
    report = _report(sample.read_bytes())
    statuses = AssuranceProviderRunner(
        {
            "sandbox_provider_command": [sys.executable, str(provider)],
            "sandbox_attestations_dir": str(tmp_path / "sandbox"),
        }
    ).collect(sample, report, allow_external=True)

    assert statuses[0]["state"] == "unavailable"
    assert "not bound" in statuses[0]["error"]


def test_provider_output_is_bounded_before_parsing(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"sample")
    provider = tmp_path / "noisy-provider.py"
    provider.write_text(
        "import sys; sys.stdout.write('x' * (1024 * 1024 + 1))",
        encoding="utf-8",
    )
    report = _report(sample.read_bytes())

    statuses = AssuranceProviderRunner(
        {
            "sandbox_provider_command": [sys.executable, str(provider)],
            "sandbox_attestations_dir": str(tmp_path / "sandbox"),
        }
    ).collect(sample, report, allow_external=True)

    assert statuses[0]["state"] == "unavailable"
    assert "exceeded 1 MiB" in statuses[0]["error"]


def test_provider_result_is_rejected_if_sample_changes_during_run(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"sample")
    provider = tmp_path / "mutating-provider.py"
    provider.write_text(
        """import json, pathlib, sys
request = json.load(sys.stdin)
pathlib.Path(request["sample_path"]).write_bytes(b"changed")
json.dump({
    "schema_version": "1.0",
    "sample_sha256": request["sample_sha256"],
    "completed": True,
    "isolation": "vm",
    "verdict": "clean",
}, sys.stdout)
""",
        encoding="utf-8",
    )
    report = _report(sample.read_bytes())

    statuses = AssuranceProviderRunner(
        {
            "sandbox_provider_command": [sys.executable, str(provider)],
            "sandbox_attestations_dir": str(tmp_path / "sandbox"),
        }
    ).collect(sample, report, allow_external=True)

    assert statuses[0]["state"] == "unavailable"
    assert "sample changed" in statuses[0]["error"]
