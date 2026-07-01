"""Tests for PemArmorDecoder (certutil / PEM base64 armor).

certutil -encode and PEM wrap base64 between -----BEGIN X----- / -----END X-----
lines; malware smuggles payloads inside fake CERTIFICATE blocks and unpacks them
with certutil -decode. The armor stops the plain base64 detector from firing.
"""

import os
import base64

from titan_decoder.decoders.base import PemArmorDecoder
from titan_decoder.core.engine import TitanEngine
from titan_decoder.config import Config


def _pem(raw: bytes, label: str = "CERTIFICATE") -> bytes:
    b = base64.b64encode(raw).decode()
    body = "\n".join(b[i:i + 64] for i in range(0, len(b), 64))
    return f"-----BEGIN {label}-----\n{body}\n-----END {label}-----\n".encode()


def test_decodes_certutil_armor():
    dec = PemArmorDecoder()
    enc = _pem(b"payload http://malware.example/c2/cert dropper")
    assert dec.can_decode(enc)
    out, ok = dec.decode(enc)
    assert ok and b"http://malware.example/c2/cert" in out


def test_multiple_blocks_concatenated():
    dec = PemArmorDecoder()
    blob = _pem(b"first http://malware.example/a") + _pem(b"second http://malware.example/b", "PRIVATE KEY")
    out, ok = dec.decode(blob)
    assert ok
    assert b"http://malware.example/a" in out and b"http://malware.example/b" in out


def test_engine_recovers_url_and_pe_from_pem():
    cfg = Config()
    cfg.set("max_recursion_depth", 10)
    # Fake "certificate" that actually smuggles a PE with an embedded URL.
    pe = b"MZ" + b"\x00" * 80 + b" http://malware.example/embed.exe " + b"\x00" * 20
    rep = TitanEngine(cfg).run_analysis(_pem(pe))
    assert "http://malware.example/embed.exe" in rep["iocs"].get("urls", [])


def test_no_fire_without_armor():
    dec = PemArmorDecoder()
    assert dec.can_decode(base64.b64encode(b"plain base64 no armor here")) is False
    assert dec.can_decode(b"just some text") is False


def test_no_crash_on_malformed_and_no_random_fp():
    dec = PemArmorDecoder()
    for bad in (b"-----BEGIN X-----", b"-----BEGIN A-----\n@@@\n-----END A-----", b""):
        assert dec.decode(bad) == (bad, False) or isinstance(dec.decode(bad), tuple)
    assert sum(1 for _ in range(2000) if dec.can_decode(os.urandom(200))) == 0
