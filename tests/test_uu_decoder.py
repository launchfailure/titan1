import binascii
import warnings

from titan_decoder.decoders.base import UUDecoder


def _uuencode(payload: bytes, name: str = "sample.txt") -> bytes:
    lines = [f"begin 644 {name}\n".encode()]
    for i in range(0, len(payload), 45):
        lines.append(binascii.b2a_uu(payload[i : i + 45]))
    lines.append(b"`\nend\n")
    return b"".join(lines)


def test_uudecode_roundtrip():
    dec = UUDecoder(enabled=True)
    for payload in (
        b"Hello, UUencoded world! http://evil.com 8.8.8.8\n",
        b"X" * 200 + b"\nsecond line\n",
        bytes(range(256)) * 3,  # full binary range
        b"a",
        b"B" * 45,  # exactly one full line
    ):
        data = _uuencode(payload)
        out, ok = dec.decode(data)
        assert ok is True
        assert out == payload


def test_uudecode_handles_crlf():
    dec = UUDecoder(enabled=True)
    payload = b"crlf test 1.2.3.4\n"
    data = _uuencode(payload).replace(b"\n", b"\r\n")
    out, ok = dec.decode(data)
    assert ok is True
    assert out == payload


def test_uudecode_emits_no_deprecation_warning():
    # Must not import the deprecated stdlib `uu` module.
    dec = UUDecoder(enabled=True)
    data = _uuencode(b"no deprecation please\n")
    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        out, ok = dec.decode(data)
    assert ok is True


def test_uudecode_graceful_on_garbage():
    dec = UUDecoder(enabled=True)
    assert dec.decode(b"random bytes, no header") == (b"random bytes, no header", False)


def test_uudecode_disabled_by_default():
    assert UUDecoder().can_decode(_uuencode(b"x" * 20)) is False
