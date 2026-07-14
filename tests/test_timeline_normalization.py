from titan_decoder.correlation.timeline import (
    TimelineEvent,
    normalize_timestamp,
    sort_timeline,
)


def test_timestamp_normalization_converts_offsets_to_utc():
    assert normalize_timestamp("2026-07-14T12:00:00-05:00") == (
        "2026-07-14T17:00:00.000000Z"
    )


def test_timeline_sort_is_stable():
    later = TimelineEvent("case-a", "2026-01-02T00:00:00Z", "analysis", "later")
    earlier = TimelineEvent("case-b", "2026-01-01T00:00:00Z", "analysis", "earlier")
    assert sort_timeline([later, earlier]) == (earlier, later)
