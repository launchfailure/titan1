import json

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from titan_decoder.core.evidence_models import (
    EvidenceRef,
    Indicator,
    merge_indicators,
)
from titan_decoder.core.evidence_parsers import _as_int, parse_evidence_file


def _canonical_indicators(indicators):
    return sorted(
        (
            item.indicator_type,
            item.value,
            item.first_seen,
            item.last_seen,
            item.confidence,
            tuple(sorted(item.tags)),
            tuple(
                sorted(
                    (
                        source.evidence_path,
                        source.extracted_by,
                        source.record_id,
                        source.field,
                    )
                    for source in item.sources
                )
            ),
        )
        for item in indicators
    )


@settings(max_examples=100, deadline=None)
@given(
    rows=st.lists(
        st.tuples(
            st.sampled_from(["domain", "domains", "ip", "ipv4"]),
            st.text(
                alphabet=st.characters(
                    blacklist_categories=("Cs",), blacklist_characters="\x00"
                ),
                min_size=1,
                max_size=24,
            ),
            st.sampled_from([None, "2025-01-01T00:00:00+00:00"]),
            st.sampled_from(["low", "medium", "high"]),
            st.lists(st.sampled_from(["dns", "proxy", "auth"]), max_size=3),
        ),
        max_size=30,
    )
)
def test_indicator_merge_is_permutation_invariant(rows):
    indicators = [
        Indicator(
            indicator_type=indicator_type,
            value=value,
            first_seen=timestamp,
            last_seen=timestamp,
            confidence=confidence,
            tags=tags,
            sources=[EvidenceRef("evidence", "property", f"line:{index}", "value")],
        )
        for index, (indicator_type, value, timestamp, confidence, tags) in enumerate(
            rows
        )
    ]

    forward = _canonical_indicators(merge_indicators(indicators))
    reverse = _canonical_indicators(merge_indicators(list(reversed(indicators))))

    assert forward == reverse


@settings(
    max_examples=100,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(
    records=st.lists(
        st.fixed_dictionaries(
            {
                "timestamp": st.sampled_from(["2025-01-01T00:00:00Z", "invalid", None]),
                "src_ip": st.one_of(st.none(), st.ip_addresses(v=4).map(str)),
                "dst_ip": st.one_of(st.none(), st.ip_addresses(v=4).map(str)),
                "domain": st.one_of(
                    st.none(),
                    st.sampled_from(["example.test", "host.invalid", "a.local"]),
                ),
                "url": st.one_of(
                    st.none(),
                    st.sampled_from(
                        ["https://example.test/a", "http://host.invalid/b"]
                    ),
                ),
                "user": st.one_of(st.none(), st.text(max_size=24)),
            }
        ),
        max_size=40,
    )
)
def test_generic_jsonl_parser_preserves_record_and_output_bounds(tmp_path, records):
    evidence = tmp_path / "property.jsonl"
    evidence.write_text(
        "\n".join(json.dumps(record) for record in records) + ("\n" if records else ""),
        encoding="utf-8",
    )

    result = parse_evidence_file(evidence, "generic")
    keys = [(item.indicator_type, item.value) for item in result.indicators]

    assert len(result.events) == len(records)
    assert len(result.indicators) <= len(records) * 6
    assert len(keys) == len(set(keys))
    assert sum(len(item.sources) for item in result.indicators) <= len(records) * 6


@settings(max_examples=200, deadline=None)
@given(
    st.one_of(
        st.none(),
        st.booleans(),
        st.integers(),
        st.floats(allow_nan=True, allow_infinity=True),
        st.text(max_size=100),
        st.binary(max_size=100),
        st.lists(st.integers(), max_size=10),
        st.dictionaries(st.text(max_size=10), st.integers(), max_size=10),
    )
)
def test_integer_coercion_is_total(value):
    result = _as_int(value)
    assert result is None or isinstance(result, int)
