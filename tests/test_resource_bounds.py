"""Property/model tests for the safety-critical resource bounds.

The decompression cap, node cap, and analysis timeout are the safety-critical
invariants that keep the engine safe on hostile input. These tests exercise them
as *properties* that must hold across many generated inputs — including the
decoded-content path, which bypasses score-based pruning and is therefore the
one most likely to blow a bound if a regression slips in.
"""

import os
import sys
import time

import pytest

from titan_decoder.core.engine import TitanEngine
from titan_decoder.config import Config
from titan_decoder.decoders.base import (
    GzipDecoder,
    Bz2Decoder,
    LzmaDecoder,
    ZlibDecoder,
    _bounded_decompress,
)

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "tests"))


def _small_config(**over):
    cfg = Config()
    cfg.set("max_node_count", over.get("max_node_count", 30))
    cfg.set("max_recursion_depth", over.get("max_recursion_depth", 6))
    cfg.set("analysis_timeout_seconds", over.get("analysis_timeout_seconds", 30))
    return cfg


# ---------------------------------------------------------------------------
# Decompression cap
# ---------------------------------------------------------------------------


def test_decompression_cap_holds_for_all_compressors():
    import bz2
    import gzip
    import lzma
    import zlib

    cap = 64 * 1024
    payload = b"A" * (8 * 1024 * 1024)  # 8 MB -> compresses tiny
    cases = [
        (GzipDecoder(cap), gzip.compress(payload)),
        (Bz2Decoder(cap), bz2.compress(payload)),
        (LzmaDecoder(cap), lzma.compress(payload)),
        (ZlibDecoder(cap), zlib.compress(payload)),
    ]
    for decoder, blob in cases:
        out, ok = decoder.decode(blob)
        # Bomb exceeds the cap: decoder declines and returns the raw input
        # unchanged, never the multi-MB expansion.
        assert len(out) <= max(cap, len(blob))


def test_bounded_decompress_raises_past_cap():
    import zlib

    blob = zlib.compress(b"B" * (4 * 1024 * 1024))
    with pytest.raises(ValueError):
        _bounded_decompress(zlib.decompressobj, blob, 32 * 1024)


def test_bounded_decompress_allows_exactly_at_cap():
    import zlib

    data = b"C" * 1000
    blob = zlib.compress(data)
    assert _bounded_decompress(zlib.decompressobj, blob, 1000) == data


# ---------------------------------------------------------------------------
# Node cap — including the decoded-content path that bypasses score pruning
# ---------------------------------------------------------------------------


def test_node_cap_holds_on_deeply_nested_archives():
    # A nested-zip fan-out exercises the is_decoded_content path, which skips
    # the score/count pruning rules; the hard node cap must still bound it.
    import io
    import zipfile

    def zip_bytes(inner: bytes, name: str) -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr(name, inner)
        return buf.getvalue()

    data = b"http://c2.example/x " * 20
    for _ in range(8):  # 8 layers of nested zips
        data = zip_bytes(data, "inner.bin")

    cap = 20
    engine = TitanEngine(_small_config(max_node_count=cap))
    report = engine.run_analysis(data)
    assert report["node_count"] <= cap


def test_node_cap_holds_on_base64_bomb():
    import base64

    data = base64.b64encode(b"payload " * 100)
    for _ in range(6):
        data = base64.b64encode(data)
    cap = 15
    engine = TitanEngine(_small_config(max_node_count=cap))
    report = engine.run_analysis(data)
    assert report["node_count"] <= cap


def test_node_cap_never_exceeded_across_random_inputs():
    cap = 12
    engine = TitanEngine(_small_config(max_node_count=cap))
    import random

    rng = random.Random(99)
    for _ in range(40):
        n = rng.randint(16, 4096)
        data = bytes(rng.randrange(256) for _ in range(n))
        report = engine.run_analysis(data)
        assert report["node_count"] <= cap


# ---------------------------------------------------------------------------
# Timeout / termination
# ---------------------------------------------------------------------------


def test_analysis_terminates_within_wall_clock_budget():
    # Even a pathological nested archive must return within a bounded time.
    import io
    import zipfile

    def zip_bytes(inner: bytes) -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("a", inner)
        return buf.getvalue()

    data = os.urandom(4096)
    for _ in range(10):
        data = zip_bytes(data)

    engine = TitanEngine(_small_config(max_node_count=50, analysis_timeout_seconds=10))
    start = time.monotonic()
    engine.run_analysis(data)
    assert time.monotonic() - start < 15.0


try:
    from hypothesis import given, settings
    from hypothesis import strategies as st

    _HAS_HYPOTHESIS = True
except Exception:  # pragma: no cover
    _HAS_HYPOTHESIS = False


if _HAS_HYPOTHESIS:

    @settings(max_examples=60, deadline=None)
    @given(st.binary(min_size=0, max_size=8192))
    def test_property_node_cap_and_termination(data):
        cap = 15
        engine = TitanEngine(_small_config(max_node_count=cap))
        start = time.monotonic()
        report = engine.run_analysis(data)
        # Bound holds for arbitrary input; run completes promptly.
        assert report["node_count"] <= cap
        assert time.monotonic() - start < 15.0
