import bz2
import gzip
import lzma
import zlib

from titan_decoder.decoders.base import (
    Bz2Decoder,
    GzipDecoder,
    LzmaDecoder,
    ZlibDecoder,
)

CAP = 1 * 1024 * 1024  # 1 MB cap for tests
BOMB = b"\x00" * (50 * 1024 * 1024)  # 50 MB of zeros -> tiny compressed payload


def test_decompression_bomb_is_rejected():
    cases = [
        (GzipDecoder(CAP), gzip.compress(BOMB)),
        (Bz2Decoder(CAP), bz2.compress(BOMB)),
        (LzmaDecoder(CAP), lzma.compress(BOMB)),
        (ZlibDecoder(CAP), zlib.compress(BOMB)),
    ]
    for decoder, payload in cases:
        out, ok = decoder.decode(payload)
        # Bomb must not expand past the cap: decode fails and returns input as-is.
        assert ok is False, decoder.name
        assert out == payload, decoder.name


def test_legit_compressed_data_still_decodes():
    text = b"hello world http://example.com 8.8.8.8"
    cases = [
        (GzipDecoder(CAP), gzip.compress(text)),
        (Bz2Decoder(CAP), bz2.compress(text)),
        (LzmaDecoder(CAP), lzma.compress(text)),
        (ZlibDecoder(CAP), zlib.compress(text)),
    ]
    for decoder, payload in cases:
        out, ok = decoder.decode(payload)
        assert ok is True, decoder.name
        assert out == text, decoder.name


def test_multi_member_gzip_is_preserved():
    payload = gzip.compress(b"part1 ") + gzip.compress(b"part2")
    out, ok = GzipDecoder(CAP).decode(payload)
    assert ok is True
    assert out == b"part1 part2"


def test_output_exactly_at_cap_is_allowed():
    payload = gzip.compress(b"A" * 100)
    out, ok = GzipDecoder(100).decode(payload)
    assert ok is True
    assert out == b"A" * 100
