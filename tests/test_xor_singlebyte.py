"""Tests for single-byte XOR recovery of ASCII-keyed payloads.

Real malware XORs config strings (C2 URLs, commands) with a single byte. When
the key keeps the output in low ASCII (e.g. 0x5A) the ciphertext has no high
bits, so the old high-bit gate skipped it entirely. And because XOR is a
bijection (zero entropy change) with no printable gain when the ciphertext is
already printable, the reveal scored 0 and was dropped -- so URL/command markers
were added to the structural score. It must NOT scramble random/plain/hex data.
"""

import os
import random

from titan_decoder.decoders.base import XorDecoder
from titan_decoder.core.engine import TitanEngine
from titan_decoder.config import Config


def _engine():
    cfg = Config()
    cfg.set("max_recursion_depth", 10)
    return TitanEngine(cfg)


def test_decoder_recovers_ascii_keyed_config():
    dec = XorDecoder()
    pt = b"config c2=http://malware.example/c2/panel"
    ct = bytes(b ^ 0x5A for b in pt)  # low key -> no high bits in ciphertext
    assert dec.can_decode(ct)
    out, ok = dec.decode(ct)
    assert ok and out == pt


def test_engine_recovers_url_from_single_byte_xor():
    eng = _engine()
    recovered = 0
    keys = [0x5A, 0x41, 0x13, 0xAA, 0x7F, 0x2E, 0x88, 0x11, 0x6C]
    for key in keys:
        ct = bytes(b ^ key for b in b"beacon http://malware.example/c2/x")
        rep = eng.run_analysis(ct)
        if "http://malware.example/c2/x" in rep["iocs"].get("urls", []):
            recovered += 1
    assert recovered >= len(keys) - 2  # allow a couple of key-ambiguity misses


def test_does_not_scramble_plain_text_or_hex_or_base64():
    dec = XorDecoder()
    import base64
    import binascii

    for data in (
        b"the quick brown fox jumps over the lazy dog repeatedly",
        binascii.hexlify(os.urandom(60)),
        base64.b64encode(os.urandom(60)),
    ):
        out, ok = dec.decode(data) if dec.can_decode(data) else (data, False)
        # Either declined, or accepted only without changing the data.
        assert not (ok and out != data)


def test_no_hallucinated_iocs_on_random_binary():
    eng = _engine()
    random.seed(11)
    fabricated = 0
    for _ in range(200):
        rep = eng.run_analysis(os.urandom(random.randint(50, 512)))
        iocs = rep.get("iocs", {})
        fabricated += len(iocs.get("urls", [])) + len(iocs.get("emails", [])) + len(iocs.get("ipv4_public", []))
    assert fabricated == 0
