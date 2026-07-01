"""Tests for Base64UrlDecoder (RFC 4648 section 5: '-'/'_' for '+'/'/').

Used by JWTs and web-based C2. It must fire only when '-' or '_' is present so
it never competes with the standard base64 decoders, and must not false-positive
on random data.
"""

import os
import base64

from titan_decoder.decoders.base import Base64UrlDecoder
from titan_decoder.core.engine import TitanEngine
from titan_decoder.config import Config


def test_decodes_urlsafe_base64():
    dec = Base64UrlDecoder()
    raw = b"config c2=http://malware.example/c2/url?x=1" + b"\xfb\xff"
    enc = base64.urlsafe_b64encode(raw)
    assert (b"-" in enc) or (b"_" in enc)
    assert dec.can_decode(enc)
    out, ok = dec.decode(enc)
    assert ok and out == raw


def test_does_not_touch_standard_base64():
    dec = Base64UrlDecoder()
    std = base64.b64encode(b"hello world some padding here")
    # Standard base64 has no '-'/'_' -> the url decoder must decline it.
    if b"-" not in std and b"_" not in std:
        assert dec.can_decode(std) is False


def test_end_to_end_url_recovery():
    cfg = Config()
    cfg.set("max_recursion_depth", 10)
    raw = b"cfg http://malware.example/c2/url?x=1" + b"\xfb\xff"
    enc = base64.urlsafe_b64encode(raw)
    rep = TitanEngine(cfg).run_analysis(enc)
    assert "http://malware.example/c2/url?x=1" in rep["iocs"].get("urls", [])


def test_no_false_positive_on_random():
    dec = Base64UrlDecoder()
    fp = sum(1 for _ in range(3000) if dec.can_decode(os.urandom(64)))
    assert fp == 0
