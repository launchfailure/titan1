"""Regression tests for ASN1Decoder structural recursion.

_parse_asn1 is documented as "Recursively parse ASN.1 structure" and carries a
``depth`` parameter with a ``depth > 10`` guard, but it never actually recursed:
it only extracted string types at the top level. Because virtually all real
ASN.1 (X.509 certs, private keys, PKCS structures) wraps its content in an outer
SEQUENCE, the decoder extracted nothing from realistic input and reported
failure. These tests pin the recursion into constructed types.
"""

import time

from titan_decoder.decoders.base import ASN1Decoder


def der(tag: int, val: bytes) -> bytes:
    """Minimal DER TLV encoder (short + long-form length)."""
    if len(val) < 128:
        return bytes([tag, len(val)]) + val
    lb = len(val).to_bytes((len(val).bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(lb)]) + lb + val


def test_extracts_strings_from_sequence():
    asn = ASN1Decoder(enabled=True)
    seq = der(0x30, der(0x13, b"hello") + der(0x04, b"worldbytes") + der(0x0C, b"utf8here"))
    out, ok = asn.decode(seq)
    assert ok is True
    assert b"hello" in out and b"worldbytes" in out and b"utf8here" in out


def test_extracts_from_nested_sequences():
    asn = ASN1Decoder(enabled=True)
    nested = der(0x30, der(0x30, der(0x13, b"deepstring")))
    out, ok = asn.decode(nested)
    assert ok is True
    assert out == b"deepstring"


def test_flat_top_level_string_still_works():
    asn = ASN1Decoder(enabled=True)
    out, ok = asn.decode(der(0x13, b"PrintableHello"))
    assert ok is True and out == b"PrintableHello"


def test_set_is_also_recursed():
    asn = ASN1Decoder(enabled=True)
    # SET (0x31) is constructed too.
    out, ok = asn.decode(der(0x31, der(0x13, b"insideset")))
    assert ok is True and b"insideset" in out


def test_deep_nesting_terminates_via_depth_guard():
    asn = ASN1Decoder(enabled=True)
    blob = der(0x13, b"core")
    for _ in range(50):
        blob = der(0x30, blob)
    t0 = time.time()
    out, ok = asn.decode(blob)  # must not recurse forever / blow the stack
    assert time.time() - t0 < 1.0
    assert isinstance(out, bytes) and isinstance(ok, bool)


def test_malformed_lengths_do_not_crash():
    asn = ASN1Decoder(enabled=True)
    for bad in (b"\x30\x84\xff\xff\xff\xff", b"\x30\x80", b"\x30\x81", b"\x31\x05\x04\x03ab"):
        out, ok = asn.decode(bad)
        assert ok is False and out == bad
