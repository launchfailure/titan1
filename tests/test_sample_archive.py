from pathlib import Path

from titan_decoder.desktop_ui.sample_archive import SampleArchive
from titan_decoder.workbench_ui.models import AnalysisSnapshot


def test_sample_archive_keeps_hidden_samples_available(tmp_path):
    archive = SampleArchive(tmp_path / "history")
    record = archive.archive_bytes(b"evidence", "sample.bin")
    snapshot = AnalysisSnapshot(
        source_name="sample.bin",
        source_size=8,
        report={"nodes": [{"id": "root"}]},
    )
    archive.attach_snapshot(record.id, snapshot)

    archive.set_latest_visibility(record.id, False)

    assert archive.records(include_hidden=False) == []
    assert archive.records(include_hidden=True)[0].id == record.id
    assert archive.load_evidence(record.id) == b"evidence"
    assert archive.load_snapshot(record.id).report == snapshot.report


def test_sample_archive_save_and_permanent_delete(tmp_path):
    archive = SampleArchive(tmp_path / "history")
    record = archive.archive_bytes(b"payload", "payload.txt")
    destination = tmp_path / "saved" / "payload.txt"

    assert archive.save_copy(record.id, destination) == destination
    assert destination.read_bytes() == b"payload"

    archive.delete_permanently(record.id)
    assert archive.records() == []
    assert not any((tmp_path / "history" / "objects").iterdir())


def test_snapshot_only_records_export_the_report(tmp_path):
    archive = SampleArchive(tmp_path / "history")
    record = archive.import_snapshot(
        AnalysisSnapshot(
            source_name="legacy.json",
            source_size=12,
            report={"analysis_outcome": {"status": "analyzed"}},
        )
    )
    destination = Path(tmp_path / "legacy-export.json")

    archive.save_copy(record.id, destination)

    assert "analysis_outcome" in destination.read_text(encoding="utf-8")


def test_deleted_legacy_report_is_not_reimported(tmp_path):
    archive = SampleArchive(tmp_path / "history")
    snapshot = AnalysisSnapshot(source_name="legacy.json", report={"nodes": []})
    source = str(tmp_path / "reports" / "legacy.json")
    record = archive.import_snapshot(snapshot, source_path=source)
    assert record is not None

    archive.delete_permanently(record.id)

    assert archive.import_snapshot(snapshot, source_path=source) is None
    assert archive.records() == []
