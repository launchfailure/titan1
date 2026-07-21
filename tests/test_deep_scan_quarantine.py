from hashlib import sha256
from pathlib import Path
import stat
import threading

import pytest

from titan_decoder import cli
from titan_decoder.config import Config
from titan_decoder.core.deep_scan import DeepScanner
from titan_decoder.core.quarantine import QuarantineVault


def test_quarantine_copy_is_hash_addressed_and_recoverable(tmp_path):
    source = tmp_path / "source.bin"
    source.write_bytes(b"malicious test bytes")
    vault = QuarantineVault(tmp_path / "vault")

    record = vault.quarantine(source, "MALICIOUS")

    assert source.is_file()
    assert Path(record.object_path).name == sha256(source.read_bytes()).hexdigest()
    assert record.source_removed is False
    restored = vault.restore(record.id, tmp_path / "restored.bin")
    assert restored.read_bytes() == source.read_bytes()
    assert vault.get(record.id) == record


def test_quarantine_move_removes_source_only_after_vault_copy(tmp_path):
    source = tmp_path / "source.bin"
    source.write_bytes(b"suspicious test bytes")
    vault = QuarantineVault(tmp_path / "vault")

    record = vault.quarantine(source, "SUSPICIOUS", move=True)

    assert record.source_removed is True
    assert not source.exists()
    restored = vault.restore(record.id)
    assert restored == source
    assert source.read_bytes() == b"suspicious test bytes"


def test_restore_rejects_tampered_quarantine_object(tmp_path):
    source = tmp_path / "source.bin"
    source.write_bytes(b"evidence")
    vault = QuarantineVault(tmp_path / "vault")
    record = vault.quarantine(source, "MALICIOUS")
    object_path = Path(record.object_path)
    object_path.chmod(stat.S_IWRITE | stat.S_IREAD)
    object_path.write_bytes(b"tampered")

    with pytest.raises(RuntimeError, match="hash verification"):
        vault.restore(record.id, tmp_path / "restored.bin")


def test_quarantine_rejects_a_tampered_existing_object(tmp_path):
    source = tmp_path / "source.bin"
    source.write_bytes(b"evidence")
    vault = QuarantineVault(tmp_path / "vault")
    record = vault.quarantine(source, "MALICIOUS")
    object_path = Path(record.object_path)
    object_path.chmod(stat.S_IWRITE | stat.S_IREAD)
    object_path.write_bytes(b"tampered")

    with pytest.raises(RuntimeError, match="failed SHA-256 verification"):
        vault.quarantine(source, "MALICIOUS")


def test_deep_scan_is_deterministic_bounded_and_quarantines_malicious(tmp_path):
    samples = tmp_path / "samples"
    samples.mkdir()
    clean = samples / "a-clean.txt"
    malicious = samples / "b-malicious.txt"
    clean.write_bytes(b"ordinary content")
    malicious.write_bytes(b"known malicious test content")
    malicious_hashes = tmp_path / "malicious.txt"
    malicious_hashes.write_text(
        f"{sha256(malicious.read_bytes()).hexdigest()} test marker\n",
        encoding="utf-8",
    )
    config = Config(tmp_path / "missing-config.json")
    config.set("malicious_hashes_path", str(malicious_hashes))
    events = []
    vault = QuarantineVault(tmp_path / "quarantine")

    summary = DeepScanner(config, progress_callback=events.append).scan(
        samples,
        reports_dir=tmp_path / "reports",
        quarantine=vault,
        quarantine_verdicts={"MALICIOUS"},
    )

    assert summary["analyzed_count"] == 2
    assert [Path(item["path"]).name for item in summary["results"]] == [
        "a-clean.txt",
        "b-malicious.txt",
    ]
    malicious_result = summary["results"][1]
    assert malicious_result["verdict"] == "MALICIOUS"
    assert malicious_result["quarantine"]["sha256"] == sha256(
        malicious.read_bytes()
    ).hexdigest()
    assert malicious.exists()  # copy is the non-destructive default
    assert len(vault.records()) == 1
    assert events[0]["current"] == 1 and events[-1]["current"] == 2


def test_deep_scan_honors_preflight_cancellation(tmp_path):
    sample = tmp_path / "sample.txt"
    sample.write_text("content", encoding="utf-8")
    cancel = threading.Event()
    cancel.set()

    summary = DeepScanner(cancel_event=cancel).scan(
        sample, reports_dir=tmp_path / "reports"
    )

    assert summary["cancelled"] is True
    assert summary["analyzed_count"] == 0


def test_deep_scan_report_names_do_not_collide_for_duplicate_paths(tmp_path):
    samples = tmp_path / "samples"
    (samples / "a").mkdir(parents=True)
    (samples / "b").mkdir(parents=True)
    (samples / "a" / "same.bin").write_bytes(b"same content")
    (samples / "b" / "same.bin").write_bytes(b"same content")
    reports = tmp_path / "reports"

    summary = DeepScanner().scan(samples, reports_dir=reports)

    assert summary["analyzed_count"] == 2
    assert len(list(reports.glob("*.json"))) == 2


def test_deep_scan_excludes_its_report_and_quarantine_roots(tmp_path):
    samples = tmp_path / "samples"
    samples.mkdir()
    (samples / "sample.txt").write_text("ordinary content", encoding="utf-8")
    reports = samples / "reports"
    reports.mkdir()
    (reports / "old.json").write_text("{}", encoding="utf-8")
    vault = QuarantineVault(samples / "quarantine")
    vault.objects.mkdir(parents=True)
    (vault.objects / "old-object").write_bytes(b"old evidence")

    summary = DeepScanner().scan(
        samples,
        reports_dir=reports,
        quarantine=vault,
    )

    assert summary["discovered_count"] == 1
    assert summary["analyzed_count"] == 1
    assert Path(summary["results"][0]["path"]).name == "sample.txt"


def test_cli_deep_scan_and_quarantine_restore_workflow(tmp_path, capsys):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"known malicious cli content")
    malicious_hashes = tmp_path / "malicious.txt"
    malicious_hashes.write_text(
        sha256(sample.read_bytes()).hexdigest() + "\n", encoding="utf-8"
    )
    quarantine = tmp_path / "quarantine"
    summary_path = tmp_path / "summary.json"
    args = cli.build_parser().parse_args(
        [
            "--deep-scan",
            str(sample),
            "--deep-scan-reports",
            str(tmp_path / "reports"),
            "--deep-scan-out",
            str(summary_path),
            "--quarantine-dir",
            str(quarantine),
            "--quarantine-verdict",
            "malicious",
            "--offline",
        ]
    )
    config = Config(tmp_path / "missing.json")
    config.set("malicious_hashes_path", str(malicious_hashes))
    cli.apply_runtime_config(args, config)

    assert cli.run_deep_scan(args, config) == 0
    assert summary_path.is_file()
    record = QuarantineVault(quarantine).records()[0]
    capsys.readouterr()

    restore_args = cli.build_parser().parse_args(
        [
            "--quarantine-dir",
            str(quarantine),
            "--quarantine-restore",
            record.id,
            "--quarantine-destination",
            str(tmp_path / "restored.bin"),
        ]
    )
    assert cli.handle_info_commands(restore_args, config) == 0
    assert (tmp_path / "restored.bin").read_bytes() == sample.read_bytes()
