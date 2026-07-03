"""Tests for the object-graph-aware PDF decoder.

The old decoder found ``stream ... endstream`` ranges with a regex and could
not resolve indirect references or see objects packed inside an object stream.
These tests assert the two capabilities called out in the roadmap: a stream
referenced only as ``5 0 R`` is extracted, and a ``/Type /ObjStm`` PDF yields
its packed objects.
"""

import base64
import zlib

from _pdf_fixtures import build_pdf, flate_stream, build_objstm_pdf
from titan_decoder.decoders.base import PDFDecoder
from titan_decoder.decoders.pdf import (
    PDFDocument,
    PDFRef,
    PDFStream,
    _lzw_decode,
    _ascii85_decode,
    _ascii_hex_decode,
)


def test_stream_referenced_only_by_indirect_object():
    js = flate_stream(b"", b"app.alert('http://evil.example/pdf-c2');")
    pdf = build_pdf(
        [
            (1, b"<< /Type /Catalog /OpenAction 3 0 R >>"),
            (3, b"<< /Type /Action /S /JavaScript /JS 5 0 R >>"),
            (5, js),
        ]
    )
    out, ok = PDFDecoder().decode(pdf)
    assert ok
    # The JS lives in object 5, reachable only via "5 0 R" from object 3.
    assert b"evil.example/pdf-c2" in out


def test_object_stream_objects_are_visible():
    pdf = build_objstm_pdf(
        [
            (2, b"<< /Type /Page /Secret (http://hidden.example/objstm) >>"),
            (4, b"(embedded-string-marker-XYZ)"),
        ]
    )
    doc = PDFDocument(pdf)
    # Objects packed inside the ObjStm are now in the table, though they appear
    # nowhere as "N G obj" in the raw bytes.
    assert (2, 0) in doc.objects
    assert (4, 0) in doc.objects
    obj2 = doc.objects[(2, 0)]
    assert isinstance(obj2, dict)
    assert obj2.get("Type") is not None

    out, ok = PDFDecoder().decode(pdf)
    assert ok
    assert b"hidden.example/objstm" in out


def test_filter_chain_ascii85_then_flate():
    payload = b"chained filters http://chain.example/x"
    enc = base64.a85encode(zlib.compress(payload))
    body = (
        b"<< /Length %d /Filter [/ASCII85Decode /FlateDecode] >>\nstream\n" % len(enc)
        + enc
        + b"\nendstream"
    )
    pdf = build_pdf([(1, b"<< /Type /Catalog >>"), (7, body)])
    out, ok = PDFDecoder().decode(pdf)
    assert ok and b"chain.example" in out


def test_ascii_hex_filter():
    payload = b"hex http://hex.example/y"
    enc = payload.hex().encode() + b">"
    body = (
        b"<< /Length %d /Filter /ASCIIHexDecode >>\nstream\n" % len(enc)
        + enc
        + b"\nendstream"
    )
    pdf = build_pdf([(1, b"<< /Type /Catalog >>"), (2, body)])
    out, ok = PDFDecoder().decode(pdf)
    assert ok and b"hex.example" in out


def test_ascii85_and_hex_primitives_roundtrip():
    data = b"the quick brown fox 12345 http://x.example/"
    assert _ascii85_decode(base64.a85encode(data)) == data
    assert _ascii_hex_decode(data.hex().encode() + b">") == data


def test_lzw_decode_known_vector():
    # PDF spec LZW example: the string "-----A---B" encodes to these bytes.
    encoded = bytes([0x80, 0x0B, 0x60, 0x50, 0x22, 0x0C, 0x0C, 0x85, 0x01])
    assert _lzw_decode(encoded) == b"-----A---B"


def test_malformed_pdf_declines_gracefully():
    for junk in (b"%PDF-1.7 not really a pdf %%EOF", b"%PDF-\x00\x01\x02%%EOF"):
        out, ok = PDFDecoder().decode(junk)
        assert ok in (True, False)


def test_decode_output_is_bounded():
    payload = b"A" * (4 * 1024 * 1024)
    pdf = build_pdf([(1, b"<< /Type /Catalog >>"), (2, flate_stream(b"", payload))])
    cap = 256 * 1024
    out, ok = PDFDecoder(cap).decode(pdf)
    assert len(out) <= cap
