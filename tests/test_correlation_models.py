from titan_decoder.correlation.models import (
    AnalysisRecord,
    EvidenceReference,
    IndicatorRecord,
    stable_id,
)


def test_stable_id_is_order_independent_for_mapping_keys():
    assert stable_id("x", {"a": 1, "b": 2}) == stable_id("x", {"b": 2, "a": 1})


def test_analysis_record_sorts_and_deduplicates_sets():
    record = AnalysisRecord(
        analysis_id="case-a",
        root_hash="abc",
        attack_ids=("T1059", "T1003", "T1059"),
        threat_tags=("loader-like", "loader-like"),
    )
    assert record.attack_ids == ("T1003", "T1059")
    assert record.threat_tags == ("loader-like",)


def test_indicator_preserves_provenance():
    ref = EvidenceReference("case-a", node_id="7", evidence_id="ev-1")
    indicator = IndicatorRecord("case-a", "Domain", "example.test", (ref,))
    payload = indicator.to_dict()
    assert payload["type"] == "domain"
    assert payload["references"] == [
        {"analysis_id": "case-a", "node_id": "7", "evidence_id": "ev-1"}
    ]


def test_analysis_round_trip():
    record = AnalysisRecord(
        analysis_id="case-a",
        root_hash="abc",
        indicators=(IndicatorRecord("case-a", "domain", "example.test"),),
        attack_ids=("T1059.001",),
        decode_chain=("base64", "utf16le"),
        metadata={"source": "fixture"},
    )
    assert AnalysisRecord.from_dict(record.to_dict()) == record
