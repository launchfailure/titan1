from titan_decoder.correlation.models import AnalysisRecord, IndicatorRecord
from titan_decoder.correlation.relationships import score_relationship


def _record(case_id: str, domain: str, attack: tuple[str, ...]) -> AnalysisRecord:
    return AnalysisRecord(
        analysis_id=case_id,
        root_hash=f"hash-{case_id}",
        indicators=(IndicatorRecord(case_id, "domain", domain),),
        attack_ids=attack,
        threat_tags=("loader-like",),
        decode_chain=("base64", "utf16le"),
    )


def test_relationship_score_is_symmetric_and_explainable():
    left = _record("case-a", "example.test", ("T1059.001",))
    right = _record("case-b", "example.test", ("T1059.001",))
    forward = score_relationship(left, right)
    reverse = score_relationship(right, left)

    assert forward == reverse
    assert forward.score == 1.0
    assert forward.confidence == "high"
    assert {item.kind for item in forward.evidence} == {
        "shared_indicator",
        "shared_attack",
        "shared_threat_tag",
        "decode_chain",
    }


def test_unrelated_records_score_zero():
    left = AnalysisRecord("case-a", "hash-a")
    right = AnalysisRecord("case-b", "hash-b")
    relationship = score_relationship(left, right)
    assert relationship.score == 0.0
    assert relationship.confidence == "none"
