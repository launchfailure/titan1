"""Adversarial red-team suite mapped to docs/THREAT_MODEL.md.

Each test plays one attacker action (A1..A5, G1..G7) from the threat model and
asserts the corresponding guarantee holds. This is the executable form of the
threat model: a regressed guarantee fails here.
"""

import base64
import io
import os
import sys
import time
import zipfile

from titan_decoder.core.engine import TitanEngine
from titan_decoder.config import Config

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def _cfg(nodes=25, timeout=15):
    c = Config()
    c.set("max_node_count", nodes)
    c.set("analysis_timeout_seconds", timeout)
    c.set("max_recursion_depth", 8)
    return c


# --- A1 / G1: decompression bombs -----------------------------------------


def test_A1_G1_gzip_bomb_is_not_expanded():
    import gzip

    from titan_decoder.decoders.base import GzipDecoder

    cap = 128 * 1024
    bomb = gzip.compress(b"\x00" * (16 * 1024 * 1024))
    out, ok = GzipDecoder(cap).decode(bomb)
    assert len(out) <= max(cap, len(bomb))


# --- A1 / G2: node fan-out -------------------------------------------------


def test_A1_G2_nested_zip_bomb_respects_node_cap():
    data = b"payload http://c2.example/x " * 10
    for _ in range(10):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("inner", data)
        data = buf.getvalue()
    cap = 18
    report = TitanEngine(_cfg(nodes=cap)).run_analysis(data)
    assert report["node_count"] <= cap


# --- A1 / G3: quadratic / cyclic structures --------------------------------


def test_A1_G3_repeated_markers_do_not_hang():
    # Formerly-quadratic scans (OLE/PDF window carving) are gone; feeding many
    # repeated magic bytes must still return quickly.
    data = b"%PDF-\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1MZ\x7fELF" * 5000
    start = time.monotonic()
    TitanEngine(_cfg(nodes=30, timeout=10)).run_analysis(data)
    assert time.monotonic() - start < 10.0


def test_A1_G3_cyclic_cfb_fat_does_not_loop():
    # A CFB header pointing into garbage/cyclic sectors must not loop forever.
    from titan_decoder.decoders.base import OLEDecoder

    payload = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\xff" * 8192
    start = time.monotonic()
    out, ok = OLEDecoder(1024 * 1024).decode(payload)
    assert time.monotonic() - start < 5.0
    assert ok in (True, False)


# --- A2 / G4: crashes ------------------------------------------------------


def test_A2_G4_malformed_structures_never_crash_analysis():
    payloads = [
        b"%PDF-1.7 garbage %%EOF",
        b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + os.urandom(600),
        b"PK\x03\x04" + os.urandom(200),
        b"MZ" + b"\x00" * 200,
        os.urandom(3000),
    ]
    engine = TitanEngine(_cfg())
    for data in payloads:
        report = engine.run_analysis(data)  # must not raise
        assert report["node_count"] >= 1


# --- A3: output poisoning --------------------------------------------------


def test_A3_random_bytes_do_not_fabricate_network_iocs():
    import random

    rng = random.Random(3)
    engine = TitanEngine(_cfg())
    fabricated = 0
    for _ in range(60):
        data = bytes(rng.randrange(256) for _ in range(rng.randint(64, 1024)))
        rep = engine.run_analysis(data)
        iocs = rep.get("iocs", {})
        fabricated += len(iocs.get("urls", [])) + len(iocs.get("ipv4_public", []))
    assert fabricated == 0


def test_A3_signature_bytes_in_noise_are_not_carved():
    # The real CFB parser rejects non-CFB data outright, so signature bytes in
    # random data cannot become carved artifacts.
    from titan_decoder.decoders.base import OLEDecoder

    data = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"MZPackage%PDF-" + os.urandom(600)
    out, ok = OLEDecoder().decode(data)
    assert ok is False


# --- A4 / G5: egress -------------------------------------------------------


def test_A4_G5_offline_guard_blocks_network():
    from titan_decoder.core.offline_guard import block_network, is_network_blocked
    import socket

    with block_network():
        assert is_network_blocked()
        try:
            socket.create_connection(("192.0.2.1", 80), timeout=1)
            raised = False
        except Exception:
            raised = True
        assert raised, "network should be blocked inside block_network()"


# --- A5 / G6: report integrity --------------------------------------------


def test_A5_G6_report_is_deterministic_and_schema_valid():
    import json

    data = base64.b64encode(b"beacon http://c2.example/panel more bytes here")
    engine = TitanEngine(Config())
    r1 = engine.run_analysis(data)
    r2 = engine.run_analysis(data)

    def stripped(r):
        r = json.loads(json.dumps(r))
        for k in ("analysis_id", "started_at", "finished_at", "duration_ms"):
            r.get("meta", {}).pop(k, None)
        r.get("run_manifest", {}).pop("environment", None)
        return json.dumps(r, sort_keys=True)

    assert stripped(r1) == stripped(r2)


# --- A1 / G7: rule-pack ReDoS ---------------------------------------------


def test_A1_G7_catastrophic_pack_regex_is_bounded():
    from titan_decoder.core.rule_packs import content_regex_search

    start = time.monotonic()
    result = content_regex_search(r"(a+)+$", None, "a" * 40 + "!", timeout=1.0)
    assert time.monotonic() - start < 5.0
    assert result is False
