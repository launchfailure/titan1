"""Shared invariant checks for fuzzing decoders and analyzers.

Every decoder and analyzer must satisfy three safety invariants on *any* input,
including random/malformed bytes:

1. **Never raise uncaught** — ``can_decode``/``decode`` (and
   ``can_analyze``/``analyze``) return normally; failures are signaled by the
   ``(data, False)`` / empty-list contract, not exceptions.
2. **Never exceed the output cap** — extracted/decoded output is bounded. Capped
   decoders honor their ``max_output_size``; the rest cannot expand output
   beyond a small multiple of the input.
3. **Always terminate quickly** — a single call completes well within the
   engine's per-decode timeout.

``check_all`` runs one input through everything and raises ``InvariantError``
on any violation. It is used by both the standalone fuzzer (``fuzz_decoders.py``)
and the in-CI Hypothesis property tests (``tests/test_fuzz_invariants.py``).
"""

from __future__ import annotations

import time

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
    XorDecoder,
    Rot13Decoder,
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
from titan_decoder.core.analyzers.base import (
    ZipAnalyzer,
    TarAnalyzer,
    PEAnalyzer,
    ELFAnalyzer,
)
from titan_decoder.core.analyzers.structured import (
    EmailAnalyzer,
    LnkAnalyzer,
    MsiAnalyzer,
    OfficeAnalyzer,
    OneNoteAnalyzer,
    RtfAnalyzer,
    ScriptAnalyzer,
)

# Small cap so bomb behavior is observable cheaply.
CAP = 256 * 1024
# A single decode/analyze call must finish comfortably under the engine's
# 10s per-decode timeout.
PER_CALL_TIMEOUT = 5.0


class InvariantError(AssertionError):
    """Raised when a decoder/analyzer violates a fuzzing invariant."""


def _decoders() -> list:
    return [
        Base64Decoder(),
        RecursiveBase64Decoder(),
        Base64UrlDecoder(),
        PemArmorDecoder(),
        GzipDecoder(CAP),
        Bz2Decoder(CAP),
        LzmaDecoder(CAP),
        ZlibDecoder(CAP),
        HexDecoder(),
        XorDecoder(),
        Rot13Decoder(),
        PDFDecoder(CAP),
        OLEDecoder(CAP),
        # Off-by-default decoders: force-enable so fuzzing actually reaches them.
        UUDecoder(enabled=True),
        ASN1Decoder(enabled=True),
        QuotedPrintableDecoder(enabled=True),
        Base32Decoder(enabled=True),
        URLDecoder(),
        HTMLEntityDecoder(),
        UnicodeEscapeDecoder(),
        Utf16Decoder(),
    ]


def _analyzers() -> list:
    structured = {
        "max_structured_artifacts": 16,
        "max_structured_total_size": CAP // 2,
        "max_structured_artifact_size": CAP // 4,
        "max_compression_ratio": 100,
    }
    return [
        ZipAnalyzer(
            {
                "max_zip_files": 25,
                "max_zip_total_size": CAP,
                "max_zip_file_size": CAP,
                "max_compression_ratio": 100,
            }
        ),
        TarAnalyzer(
            {
                "max_tar_files": 25,
                "max_tar_total_size": CAP,
                "max_tar_file_size": CAP,
                "max_compression_ratio": 100,
            }
        ),
        PEAnalyzer(),
        ELFAnalyzer(),
        EmailAnalyzer(structured),
        LnkAnalyzer(),
        MsiAnalyzer(structured),
        OfficeAnalyzer(structured),
        OneNoteAnalyzer(structured),
        RtfAnalyzer(structured),
        ScriptAnalyzer(structured),
    ]


def _output_bound(data: bytes) -> int:
    # Capped decoders honor CAP; the uncapped ones (base64/hex/url/...) shrink or
    # only marginally grow, so a small multiple of input plus slack is a safe
    # universal ceiling that still flags runaway expansion.
    return max(CAP, len(data) * 8 + 4096)


def check_all(data: bytes) -> None:
    """Run ``data`` through every decoder and analyzer, enforcing invariants."""
    bound = _output_bound(data)

    for dec in _decoders():
        name = dec.name
        start = time.monotonic()
        try:
            can = dec.can_decode(data)
        except Exception as e:  # invariant 1
            raise InvariantError(f"{name}.can_decode raised: {e!r}") from e
        if can:
            try:
                out, ok = dec.decode(data)
            except Exception as e:  # invariant 1
                raise InvariantError(f"{name}.decode raised: {e!r}") from e
            if not isinstance(out, (bytes, bytearray)):
                raise InvariantError(f"{name}.decode returned non-bytes: {type(out)}")
            if not isinstance(ok, bool):
                raise InvariantError(f"{name}.decode returned non-bool success flag")
            if len(out) > bound:  # invariant 2
                raise InvariantError(
                    f"{name}.decode output {len(out)} exceeds bound {bound}"
                )
        elapsed = time.monotonic() - start
        if elapsed > PER_CALL_TIMEOUT:  # invariant 3
            raise InvariantError(f"{name} took {elapsed:.2f}s (> {PER_CALL_TIMEOUT}s)")

    for an in _analyzers():
        name = an.name
        start = time.monotonic()
        try:
            can = an.can_analyze(data)
        except Exception as e:
            raise InvariantError(f"{name}.can_analyze raised: {e!r}") from e
        if can:
            try:
                extracted = an.analyze(data)
            except Exception as e:
                raise InvariantError(f"{name}.analyze raised: {e!r}") from e
            if not isinstance(extracted, list):
                raise InvariantError(f"{name}.analyze returned non-list")
            total = 0
            for item in extracted:
                if not (isinstance(item, tuple) and len(item) == 2):
                    raise InvariantError(f"{name}.analyze item not a 2-tuple")
                total += len(item[1])
            if total > bound:
                raise InvariantError(
                    f"{name}.analyze extracted {total} exceeds bound {bound}"
                )
        elapsed = time.monotonic() - start
        if elapsed > PER_CALL_TIMEOUT:
            raise InvariantError(f"{name} took {elapsed:.2f}s (> {PER_CALL_TIMEOUT}s)")
