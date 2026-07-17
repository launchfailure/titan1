"""Regression tests for Base64Decoder.

Two bugs previously lived in Base64Decoder.decode:

1. ``data.splitlines()`` yields ``bytes``, but the code called ``line.encode()``
   (a ``str`` method), raising AttributeError on every input. The decoder caught
   it and returned ``(data, False)``, so it never actually decoded anything — it
   only appeared to work in the engine because RecursiveBase64Decoder (registered
   first) handled base64 instead.
2. It decoded each line separately and joined with ``b"\\n"``, injecting spurious
   newlines that corrupted line-wrapped (PEM/MIME/``-enc``) binary payloads.
"""

import base64

from titan_decoder.decoders.base import Base64Decoder


def test_single_line_roundtrip():
    dec = Base64Decoder()
    for original in (b"hello world, triage payload 123", bytes(range(256)), b"a" * 500):
        out, ok = dec.decode(base64.b64encode(original))
        assert ok is True
        assert out == original


def test_line_wrapped_binary_reconstructs_exactly():
    """PEM/MIME-style wrapping must not inject bytes into the decoded payload."""
    dec = Base64Decoder()
    payload = bytes(range(256)) * 3
    enc = base64.b64encode(payload)
    for width, sep in ((64, b"\n"), (76, b"\r\n")):
        wrapped = sep.join(enc[i : i + width] for i in range(0, len(enc), width))
        out, ok = dec.decode(wrapped)
        assert ok is True
        assert out == payload, f"width={width} sep={sep!r} corrupted payload"


def test_non_base64_returns_failure_not_hallucination():
    dec = Base64Decoder()
    for bad in (
        b"\x00\x01\x02 not base64 !!!",
        b"short",
        b"%" * 32,
        b"",
        b"\xff\xfe\xfd",
    ):
        out, ok = dec.decode(bad)
        assert ok is False
        assert out == bad


def test_can_decode_consistent_with_decode():
    dec = Base64Decoder()
    enc = base64.b64encode(b"the quick brown fox jumps over the lazy dog")
    assert dec.can_decode(enc) is True
    out, ok = dec.decode(enc)
    assert ok is True and out == b"the quick brown fox jumps over the lazy dog"
