from titan_decoder.correlation.database import CorrelationDatabase
from titan_decoder.correlation.engine import CorrelationEngine
from titan_decoder.correlation.models import AnalysisRecord, IndicatorRecord


def _record(case_id: str, domain: str) -> AnalysisRecord:
    return AnalysisRecord(
        analysis_id=case_id,
        root_hash=f"hash-{case_id}",
        indicators=(IndicatorRecord(case_id, "domain", domain),),
    )


def test_engine_correlates_before_recording_subject(tmp_path):
    with CorrelationDatabase(tmp_path / "correlation.sqlite3") as database:
        database.record_analysis(_record("prior", "example.test"))
        engine = CorrelationEngine(database)
        report = engine.correlate(_record("current", "example.test"))

        assert report.subject_analysis_id == "current"
        assert len(report.relationships) == 1
        assert report.relationships[0].right_analysis_id == "prior"
        assert database.get_analysis("current") is not None
