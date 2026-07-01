"""Regression tests for the global node-count cap on extracted/decoded content.

Recursion into decoded content and analyzer-extracted files is marked
``is_decoded_content=True``, which makes ``should_prune_node`` return False and
skips the pre-analysis prune check. That is intentional for *score* pruning
(we always want to follow a successful decode), but it also bypassed the
count-based caps, so a small crafted nested archive could fan out to millions
of nodes (max_node_count unenforced) and exhaust memory. A hard global
node-count guard now applies to all content.
"""

import io
import zipfile

from titan_decoder.core.engine import TitanEngine
from titan_decoder.config import Config


def _make_zip(entries):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, content in entries:
            z.writestr(name, content)
    return buf.getvalue()


def _nested_archive(fan=8):
    """Outer zip -> middle zips -> inner zips -> distinct leaf files."""
    inner = [
        (f"in_{a}_{b}.zip", _make_zip([(f"{a}_{b}_l{i}.txt", f"u-{a}-{b}-{i}".encode())
                                       for i in range(fan)]))
        for a in range(fan) for b in range(fan)
    ]
    middle = [(f"mid_{a}.zip", _make_zip(inner[a * fan:(a + 1) * fan])) for a in range(fan)]
    return _make_zip(middle)


def test_nested_archive_respects_node_cap():
    cfg = Config()
    cap = cfg.get("max_node_count")
    eng = TitanEngine(cfg)
    rep = eng.run_analysis(_nested_archive(fan=8))
    # Without the guard this produced ~585 nodes for an 8-fan tree (and could
    # reach millions with fan=25); it must now stay within the configured cap.
    assert rep["node_count"] <= cap


def test_node_cap_scales_with_config():
    data = _nested_archive(fan=8)
    small = TitanEngine(_cfg(max_node_count=30)).run_analysis(data)
    big = TitanEngine(_cfg(max_node_count=200)).run_analysis(data)
    assert small["node_count"] <= 30
    assert big["node_count"] <= 200
    # A larger cap should let strictly more of the tree through here.
    assert big["node_count"] > small["node_count"]


def test_simple_payload_still_fully_analyzed():
    import base64

    eng = TitanEngine(Config())
    payload = base64.b64encode(base64.b64encode(b"powershell -enc http://evil.test/x"))
    rep = eng.run_analysis(payload)
    assert rep["node_count"] >= 2  # peeled both base64 layers
    assert "http://evil.test/x" in rep["iocs"].get("urls", [])


def test_dedup_still_prunes_identical_content():
    eng = TitanEngine(Config())
    data = _make_zip([(f"f{i}.txt", b"IDENTICAL-CONTENT-BLOB") for i in range(10)])
    rep = eng.run_analysis(data)
    pruned = sum(1 for n in rep["nodes"] if n.get("pruned"))
    assert pruned >= 1  # duplicate extracted files collapse via hash dedup


def _cfg(**overrides):
    c = Config()
    for k, v in overrides.items():
        c.set(k, v)
    return c
