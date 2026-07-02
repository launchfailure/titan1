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
    (_, meta_json), = analyzer.analyze(bytes(data))
    assert b'"ARM Thumb-2"' in meta_json
    assert b"ARM64" not in meta_json
