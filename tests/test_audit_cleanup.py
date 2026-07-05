"""Regression tests for the 2026-07 audit cleanup.

Covers:
- _bounded_decompress: trailing garbage after a complete stream no longer
  discards the decoded content (padding/appended data are common in real
  samples), while a truncated/invalid first stream still fails the decode.
- _lzw_decode: the output cap is a hard stop (previously a ``break`` only
  exited the inner loop, so output kept growing past the cap).
"""

import gzip
import zlib

from titan_decoder.decoders.base import GzipDecoder, ZlibDecoder, _bounded_decompress
from titan_decoder.decoders.pdf import _lzw_decode


PLAINTEXT = b"beacon http://c2.example/panel " * 20


def test_gzip_with_zero_padding_decodes():
    data = gzip.compress(PLAINTEXT, mtime=0) + b"\x00" * 512
    out, ok = GzipDecoder().decode(data)
    assert ok
    assert out == PLAINTEXT


def test_gzip_with_appended_garbage_decodes():
    data = gzip.compress(PLAINTEXT, mtime=0) + b"not a gzip stream at all"
    out, ok = GzipDecoder().decode(data)
    assert ok
    assert out == PLAINTEXT


def test_gzip_multimember_still_concatenates():
    data = gzip.compress(b"first ", mtime=0) + gzip.compress(b"second", mtime=0)
    out, ok = GzipDecoder().decode(data)
    assert ok
    assert out == b"first second"


def test_gzip_complete_member_then_truncated_member_keeps_first():
    second = gzip.compress(b"second member payload", mtime=0)
    data = gzip.compress(PLAINTEXT, mtime=0) + second[: len(second) // 2]
    out, ok = GzipDecoder().decode(data)
    assert ok
    # The partial second member must not leak partial output into the result.
    assert out == PLAINTEXT


def test_truncated_first_stream_still_fails():
    full = gzip.compress(PLAINTEXT, mtime=0)
    data = full[: len(full) // 2]
    out, ok = GzipDecoder().decode(data)
    assert not ok
    assert out == data


def test_zlib_with_trailing_garbage_decodes():
    data = zlib.compress(PLAINTEXT) + b"\xff\xfe trailing"
    out, ok = ZlibDecoder().decode(data)
    assert ok
    assert out == PLAINTEXT


def test_bounded_decompress_output_cap_still_enforced():
    bomb = zlib.compress(b"\x00" * 100_000)
    try:
        _bounded_decompress(zlib.decompressobj, bomb, max_output=1024)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for over-cap output")


def _pack_9bit_codes(codes):
    """Pack a list of 9-bit LZW codes into bytes (MSB-first)."""
    acc = 0
    nbits = 0
    out = bytearray()
    for code in codes:
        acc = (acc << 9) | code
        nbits += 9
        while nbits >= 8:
            nbits -= 8
            out.append((acc >> nbits) & 0xFF)
    if nbits:
        out.append((acc << (8 - nbits)) & 0xFF)
    return bytes(out)


def test_lzw_decode_hard_output_cap():
    # 100 literal codes would decode to 100 bytes; with max_output=16 the
    # decoder must stop at exactly 16 rather than continuing past the cap.
    data = _pack_9bit_codes([65] * 100)
    out = _lzw_decode(data, max_output=16)
    assert out == b"A" * 16


def test_lzw_decode_uncapped_roundtrip():
    data = _pack_9bit_codes([72, 105, 257])  # "Hi" + EOD
    assert _lzw_decode(data) == b"Hi"
