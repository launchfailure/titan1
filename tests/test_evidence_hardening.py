import time

from titan_decoder.core.evidence_models import (
    EvidenceRef,
    Indicator,
    merge_indicators,
)
from titan_decoder.core.evidence_parsers import parse_evidence_file


def _ind(value, line, conf="low", tags=("t",)):
    return Indicator(
        indicator_type="domains",
        value=value,
        first_seen=f"2025-01-01T00:00:{line % 60:02d}Z",
        last_seen=None,
        confidence=conf,
        tags=list(tags),
        sources=[EvidenceRef("p", "e", f"line:{line}", "domain")],
    )


def test_merge_indicators_dedupes_and_unions():
    inds = [
        _ind("a.com", 1, conf="low", tags=("t1",)),
        _ind("a.com", 1, conf="high", tags=("t2",)),  # duplicate source
        _ind("a.com", 2, conf="low", tags=("t1",)),  # new source
    ]
    merged = merge_indicators(inds)
    assert len(merged) == 1
    m = merged[0]
    assert len(m.sources) == 2  # duplicate source not re-added
    assert m.confidence == "high"
    assert m.tags == ["t1", "t2"]


def test_merge_indicators_is_linear_for_repeated_value():
    # The same value across many records (a recurring C2 domain) must not be
    # O(n^2). O(n^2) here would take tens of seconds; O(n) is well under a second.
    inds = [_ind("evil.com", i) for i in range(40000)]
    start = time.monotonic()
    merged = merge_indicators(inds)
    elapsed = time.monotonic() - start
    assert len(merged) == 1
    assert len(merged[0].sources) == 40000
    assert elapsed < 5.0, (
        f"merge_indicators too slow ({elapsed:.1f}s) - O(n^2) regression"
    )


def test_csv_oversized_field_does_not_abort_file(tmp_path):
    # A field larger than the old 128 KB csv limit used to raise and discard the
    # entire file. The bad row should be tolerated and other rows still parsed.
    csv_path = tmp_path / "dns.csv"
    csv_path.write_text(
        "timestamp,client_ip,query,answers\n"
        "2025-01-01T00:00:01Z,10.0.0.1," + ("a" * 200000) + ",1.2.3.4\n"
        "2025-01-01T00:00:02Z,10.0.0.2,evil.com,9.9.9.9\n"
    )
    res = parse_evidence_file(csv_path, "dns")
    vals = {(i.indicator_type, i.value) for i in res.indicators}
    assert ("domains", "evil.com") in vals
    assert ("ipv4", "9.9.9.9") in vals


def test_csv_nul_byte_row_is_tolerated(tmp_path):
    csv_path = tmp_path / "dns.csv"
    csv_path.write_bytes(
        b"timestamp,client_ip,query,answers\n"
        b"2025-01-01T00:00:01Z,10.0.0.1,evil\x00.com,1.2.3.4\n"
        b"2025-01-01T00:00:02Z,10.0.0.2,good.com,8.8.8.8\n"
    )
    res = parse_evidence_file(csv_path, "dns")
    vals = {(i.indicator_type, i.value) for i in res.indicators}
    assert ("domains", "good.com") in vals


def test_source_preview_preserved_across_indicators(tmp_path):
    # The per-record preview is now computed once and shared; ensure each
    # indicator's source still carries the record snapshot as provenance.
    csv_path = tmp_path / "dns.csv"
    csv_path.write_text(
        "timestamp,client_ip,query,answers\n"
        "2025-01-01T00:00:01Z,10.0.0.7,evil.com,203.0.113.9\n"
    )
    res = parse_evidence_file(csv_path, "dns")
    for ind in res.indicators:
        assert ind.sources, ind.value
        prev = ind.sources[0].preview
        # Every source carries a record snapshot mentioning the queried domain.
        assert prev and "evil.com" in prev
    # The client_ip / answer indicators snapshot the full record.
    full = [i for i in res.indicators if i.indicator_type == "ipv4"]
    assert full and "client_ip" in full[0].sources[0].preview
