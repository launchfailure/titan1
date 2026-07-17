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


def test_uudecode_corrupt_line_keeps_rest():
    # A single corrupt data line used to abort the whole decode (the retry's
    # exception escaped to the blanket handler), discarding every line already
    # recovered. Corrupt lines must be skipped, keeping the rest.
    dec = UUDecoder(enabled=True)
    payload = b"A" * 45 + b"B" * 45 + b"C" * 45
    data = _uuencode(payload)
    lines = data.split(b"\n")
    lines[2] = b"\x7f!!! not a valid uu line !!!"  # clobber the middle data line
    out, ok = dec.decode(b"\n".join(lines))
    assert ok is True
    assert out == b"A" * 45 + b"C" * 45
