"""Tests for the CFB (OLE2) structural parser and MS-OVBA VBA decompression.

These replace the assumptions behind the old signature-window carver: extracted
artifacts must be named after real CFB stream paths, a crafted macro document
must yield the actual decompressed VBA source, and signature bytes sitting in
random data must no longer produce carved false positives.
"""

import os
import time

from _cfb_fixtures import build_cfb, build_vba_doc, compress_ovba
from titan_decoder.decoders.cfb import CFBReader, decompress_ovba
from titan_decoder.decoders.base import OLEDecoder


VBA_SOURCE = (
    b'Attribute VB_Name = "Module1"\r\n'
    b"Sub AutoOpen()\r\n"
    b'  Dim u As String\r\n'
    b'  u = "http://evil.example/c2/panel"\r\n'
    b'  Shell "powershell -enc SQBFAFgA", vbHide\r\n'
    b"End Sub\r\n"
) * 4


def test_ovba_roundtrip():
    comp = compress_ovba(VBA_SOURCE)
    assert comp[0] == 0x01
    assert decompress_ovba(comp) == VBA_SOURCE


def test_streams_named_by_real_path():
    doc = build_cfb(
        [
            ("Macros/VBA/Module1", b"x" * 50),
            ("WordDocument", b"body" * 30),
            ("\x05SummaryInformation", b"meta-data-here"),
        ]
    )
    reader = CFBReader(doc)
    paths = sorted(p for p, _ in reader.streams())
    assert "Macros/VBA/Module1" in paths
    assert "WordDocument" in paths
    assert "\x05SummaryInformation" in paths


def test_stream_content_is_exact():
    big = b"MZ" + os.urandom(6000)
    small = b"hello world " * 5
    doc = build_cfb([("BigStream", big), ("Storage/Small", small)])
    reader = CFBReader(doc)
    got = {p: reader.read_stream(e) for p, e in reader.streams()}
    assert got["BigStream"] == big
    assert got["Storage/Small"] == small


def test_crafted_macro_yields_decompressed_vba_source():
    doc = build_vba_doc("Module1", VBA_SOURCE)
    out, ok = OLEDecoder().decode(doc)
    assert ok
    # Artifact is labeled with the real stream path, not an offset window.
    assert b"Macros/VBA/Module1" in out
    # And the actual decompressed VBA source is present (not the packed bytes).
    assert b"http://evil.example/c2/panel" in out
    assert b"Sub AutoOpen()" in out


def test_no_false_positive_on_random_data_after_magic():
    # The old carver matched signature bytes (MZ, Package, %PDF-, ...) inside
    # random data and emitted windows around them. A real CFB parser rejects
    # non-CFB data outright, so there is nothing to carve.
    for _ in range(20):
        junk = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + os.urandom(1000)
        out, ok = OLEDecoder().decode(junk)
        assert ok is False
        assert out == junk


def test_parser_is_bounded_on_hostile_input():
    # Truncated/garbage CFB headers must fail fast, not hang or crash.
    start = time.monotonic()
    for payload in (
        b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 4096,
        b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\xff" * 4096,
        b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + os.urandom(50000),
    ):
        out, ok = OLEDecoder(5 * 1024 * 1024).decode(payload)
        assert ok in (True, False)
    assert time.monotonic() - start < 5.0


def test_output_is_bounded_by_cap():
    # A doc with a large stream must not emit more than the configured cap.
    big = b"A" * (2 * 1024 * 1024)
    doc = build_cfb([("Big", big)])
    cap = 256 * 1024
    out, ok = OLEDecoder(cap).decode(doc)
    assert len(out) <= cap
