from titan_decoder.correlation.database import (
    DATABASE_SCHEMA_VERSION,
    CorrelationDatabase,
)
from titan_decoder.correlation.models import AnalysisRecord, IndicatorRecord


def _record(case_id: str, domain: str) -> AnalysisRecord:
    return AnalysisRecord(
        analysis_id=case_id,
        root_hash=f"hash-{case_id}",
        indicators=(IndicatorRecord(case_id, "domain", domain),),
    )


def test_database_upsert_and_lookup(tmp_path):
    path = tmp_path / "correlation.sqlite3"
    with CorrelationDatabase(path) as database:
        database.record_analysis(_record("case-a", "example.test"))
        database.record_analysis(_record("case-a", "changed.test"))
        loaded = database.get_analysis("case-a")
        assert loaded is not None
        assert loaded.indicators[0].value == "changed.test"
        assert database.schema_version() == DATABASE_SCHEMA_VERSION


def test_database_indicator_query_is_deterministic(tmp_path):
    with CorrelationDatabase(tmp_path / "correlation.sqlite3") as database:
        database.record_analysis(_record("case-b", "example.test"))
        database.record_analysis(_record("case-a", "example.test"))
        assert database.analyses_for_indicators(
            [("domain", "example.test")]
        ) == ("case-a", "case-b")
