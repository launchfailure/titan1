"""Regression: UU smart-detection must accept the full 0x20..0x60 alphabet.

The line class was [`!-_], which excludes space (0x20). binascii.b2a_uu emits
space for the value 0, so real UUencoded data lines containing spaces failed to
match, and _detect_uuencode under-counted lines and missed valid files -- the
UUEncode decoder is off-by-default and only enabled by this detection.
"""

import io
import binascii

from titan_decoder.core.smart_detection import SmartDetectionEngine
from titan_decoder.core.engine import TitanEngine
from titan_decoder.config import Config


def _uuenc(b: bytes) -> bytes:
    out = io.BytesIO()
    out.write(b"begin 644 f\n")
    i = 0
    while i < len(b):
        out.write(binascii.b2a_uu(b[i : i + 45]))
        i += 45
    out.write(b"`\nend\n")
    return out.getvalue()


def test_uu_with_space_chars_is_detected():
    # This payload encodes to UU lines that contain 0x20 space characters.
    enc = _uuenc(b"stage http://malware.example/stage2/uu")
    detections = dict(SmartDetectionEngine().detect_format(enc))
    assert "uuencode" in detections


def test_engine_recovers_url_from_uuencoded_payload():
    cfg = Config()
    cfg.set("max_recursion_depth", 10)
    enc = _uuenc(b"stage http://malware.example/stage2/uu")
    rep = TitanEngine(cfg).run_analysis(enc)
    assert "http://malware.example/stage2/uu" in rep["iocs"].get("urls", [])
