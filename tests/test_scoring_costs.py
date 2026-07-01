"""Regression test for ScoringEngine.DECODER_COSTS key alignment.

The cost table is keyed by decoder/analyzer ``.name``. If a key doesn't match a
real name, the lookup silently falls back to the default cost and that decoder
is mis-scored. Historically "Lzma"/"Rot13" never matched the real "LZMA"/"ROT13"
and "ZLIB" was missing, so three decoders were mis-costed.
"""

from titan_decoder.core.scoring import ScoringEngine
from titan_decoder.core.analyzers.base import (
    ZipAnalyzer,
    TarAnalyzer,
    PEAnalyzer,
    ELFAnalyzer,
)
from titan_decoder.decoders.base import (
    Base64Decoder,
    RecursiveBase64Decoder,
    Base64UrlDecoder,
    PemArmorDecoder,
    GzipDecoder,
    Bz2Decoder,
    LzmaDecoder,
    ZlibDecoder,
    HexDecoder,
    Rot13Decoder,
    XorDecoder,
    PDFDecoder,
    OLEDecoder,
    UUDecoder,
    ASN1Decoder,
    QuotedPrintableDecoder,
    Base32Decoder,
    URLDecoder,
    HTMLEntityDecoder,
    UnicodeEscapeDecoder,
    Utf16Decoder,
)

ALL_NAMES = {
    d().name
    for d in (
        Base64Decoder, RecursiveBase64Decoder, Base64UrlDecoder, PemArmorDecoder,
        GzipDecoder, Bz2Decoder, LzmaDecoder, ZlibDecoder, HexDecoder, Rot13Decoder,
        XorDecoder, PDFDecoder, OLEDecoder, Utf16Decoder,
    )
} | {
    UUDecoder().name, ASN1Decoder().name, QuotedPrintableDecoder().name,
    Base32Decoder().name, URLDecoder().name, HTMLEntityDecoder().name,
    UnicodeEscapeDecoder().name,
} | {ZipAnalyzer().name, TarAnalyzer().name, PEAnalyzer().name, ELFAnalyzer().name}


def test_no_orphan_cost_keys():
    """Every DECODER_COSTS key must correspond to a real decoder/analyzer name."""
    orphans = [k for k in ScoringEngine.DECODER_COSTS if k not in ALL_NAMES]
    assert orphans == [], f"DECODER_COSTS keys with no matching .name: {orphans}"


def test_previously_mismatched_names_are_present():
    for name in ("LZMA", "ROT13", "ZLIB"):
        assert name in ScoringEngine.DECODER_COSTS


def test_rot13_cheaper_than_lzma_in_cost_component():
    # ROT13 (cost 1) must score higher on the cost component than LZMA (cost 4);
    # before the fix both silently resolved to the same default cost.
    rot13_cost = ScoringEngine._decoder_cost_score("ROT13", 0)
    lzma_cost = ScoringEngine._decoder_cost_score("LZMA", 0)
    assert rot13_cost > lzma_cost
