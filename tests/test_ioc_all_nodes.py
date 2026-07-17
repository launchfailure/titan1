"""Regression test: IOCs must be extracted from all node previews, not just
Text-classified ones.

run_analysis previously joined only ``content_type == "Text"`` node previews for
IOC extraction. Malware routinely embeds C2 URLs/IPs in otherwise-binary content
(config blobs, shellcode, a readable URL followed by binary padding), which
tips ``looks_like_text`` to "Binary" and silently dropped the indicators.
"""

import io
import os
import binascii

from titan_decoder.core.engine import TitanEngine
from titan_decoder.config import Config


def _engine():
    cfg = Config()
    cfg.set("max_recursion_depth", 8)
    return TitanEngine(cfg)


def test_url_in_binary_blob_is_extracted():
    # A URL embedded between random binary padding -> node classifies Binary.
    blob = os.urandom(64) + b" c2=http://c2.binary.test/gate " + os.urandom(64)
    rep = _engine().run_analysis(blob)
    assert "http://c2.binary.test/gate" in rep["iocs"].get("urls", [])


def test_public_ip_in_binary_blob_is_extracted():
    # 8.8.8.8 is a genuinely global/routable address (documentation ranges like
    # 203.0.113.0/24 are correctly classified non-global by ipaddress.is_global).
    blob = os.urandom(48) + b" callback 8.8.8.8 now " + os.urandom(48)
    rep = _engine().run_analysis(blob)
    assert "8.8.8.8" in rep["iocs"].get("ipv4_public", [])


def test_uuencoded_payload_with_binary_tail_recovers_url():
    def uuenc(b):
        out = io.BytesIO()
        out.write(b"begin 644 f\n")
        i = 0
        while i < len(b):
            out.write(binascii.b2a_uu(b[i : i + 45]))
            i += 45
        out.write(b"`\nend\n")
        return out.getvalue()

    payload = b"secret http://uu.evil.test/beacon " + bytes(range(200, 220))
    rep = _engine().run_analysis(uuenc(payload))
    assert "http://uu.evil.test/beacon" in rep["iocs"].get("urls", [])


def test_random_binary_does_not_fabricate_network_iocs():
    eng = _engine()
    fabricated = 0
    for _ in range(200):
        rep = eng.run_analysis(os.urandom(512))
        iocs = rep.get("iocs", {})
        fabricated += len(iocs.get("urls", [])) + len(iocs.get("ipv4_public", []))
    assert fabricated == 0
