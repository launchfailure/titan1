"""Regression tests for bounded image/media hidden-payload extraction."""

from __future__ import annotations

import struct
import zlib

from titan_decoder.config import Config
from titan_decoder.core.analyzers.steganography import (
    MediaPayloadDecoder,
    SteganographyAnalyzer,
)
from titan_decoder.core.detection_rules import CorrelationRulesEngine
from titan_decoder.core.engine import TitanEngine
from titan_decoder.interactive import build_decoder_registry
from titan_decoder.workbench_ui.services import WorkbenchServices


def _synchsafe(value: int) -> bytes:
    return bytes(
        (
            (value >> 21) & 0x7F,
            (value >> 14) & 0x7F,
            (value >> 7) & 0x7F,
            value & 0x7F,
        )
    )


def _png_chunk(kind: bytes, payload: bytes) -> bytes:
    body = kind + payload
    return (
        len(payload).to_bytes(4, "big")
        + body
        + (zlib.crc32(body) & 0xFFFFFFFF).to_bytes(4, "big")
    )


def _png(width: int, height: int, pixels: bytes) -> bytes:
    assert len(pixels) == width * height * 3
    rows = b"".join(
        b"\x00" + pixels[row * width * 3 : (row + 1) * width * 3]
        for row in range(height)
    )
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + _png_chunk(b"IHDR", ihdr)
        + _png_chunk(b"IDAT", zlib.compress(rows))
        + _png_chunk(b"IEND", b"")
    )


def _lsb_carrier(payload: bytes, carrier_size: int) -> bytes:
    framed = b"TITANSTEG\x00" + len(payload).to_bytes(4, "big") + payload
    bits = [(value >> shift) & 1 for value in framed for shift in range(7, -1, -1)]
    assert len(bits) <= carrier_size
    return bytes(
        0x80 | (bits[index] if index < len(bits) else 0)
        for index in range(carrier_size)
    )


def _wav_with_lsb(payload: bytes) -> bytes:
    samples = _lsb_carrier(payload, 2048)
    fmt = struct.pack("<HHIIHH", 1, 1, 8000, 8000, 1, 8)
    chunks = b"fmt " + len(fmt).to_bytes(4, "little") + fmt
    chunks += b"data" + len(samples).to_bytes(4, "little") + samples
    return b"RIFF" + (len(chunks) + 4).to_bytes(4, "little") + b"WAVE" + chunks


def test_clean_png_does_not_create_false_hidden_payload():
    data = _png(2, 2, b"\x80" * 12)
    analyzer = SteganographyAnalyzer()
    assert analyzer.can_analyze(data)
    assert analyzer.analyze(data) == []


def test_png_appended_payload_is_extracted():
    hidden = b"MZ" + b"hidden executable marker"
    data = _png(1, 1, b"\x80\x80\x80") + hidden
    extracted = SteganographyAnalyzer().analyze(data)
    assert extracted == [("steg_png_appended_payload.exe", hidden)]


def test_png_lsb_framed_payload_is_recovered():
    hidden = b"https://evil.example.test/payload"
    pixels = _lsb_carrier(hidden, 32 * 16 * 3)
    extracted = SteganographyAnalyzer().analyze(_png(32, 16, pixels))
    assert ("steg_png_lsb_payload.txt", hidden) in extracted


def test_wav_pcm_lsb_framed_payload_is_recovered():
    hidden = b"powershell -nop -w hidden"
    extracted = SteganographyAnalyzer().analyze(_wav_with_lsb(hidden))
    assert ("steg_wav_lsb_payload.txt", hidden) in extracted


def test_manual_media_decoder_and_registry():
    hidden = b"PK\x03\x04archive payload"
    carrier = _png(1, 1, b"\x80\x80\x80") + hidden
    decoded, success = MediaPayloadDecoder().decode(carrier)
    assert success is True
    assert decoded == hidden
    assert "steganography_media" in {choice.key for choice in build_decoder_registry()}


def test_engine_adds_hidden_payload_to_decode_tree(tmp_path):
    hidden = b"https://evil.example.test/stage"
    pixels = _lsb_carrier(hidden, 32 * 16 * 3)
    cfg = Config(tmp_path / "does-not-exist.json")
    report = TitanEngine(cfg).run_analysis(_png(32, 16, pixels))
    root = report["nodes"][0]
    assert root["method"] == "ANALYZE_Steganography"
    assert root["decoder_used"] == "Steganography"
    assert any(
        node.get("artifact_name") == "steg_png_lsb_payload.txt"
        for node in report["nodes"]
    )
    assert hidden.decode() in report["iocs"]["urls"]


def test_hidden_media_rule_and_workbench_assurance(tmp_path):
    hidden = b"MZ" + b"not executed"
    carrier = _png(1, 1, b"\x80\x80\x80") + hidden
    cfg = Config(tmp_path / "does-not-exist.json")
    snapshot = WorkbenchServices(cfg).analyze(carrier, "carrier.png")
    detections = snapshot.report.get("detections", [])
    assert any(item.get("rule_id") == "TITAN-008" for item in detections)
    direct = CorrelationRulesEngine().evaluate_all(
        snapshot.report, snapshot.report["iocs"]
    )
    assert any(item["attack_ids"] == ["T1027.003"] for item in direct)


def test_webp_xmp_metadata_payload_is_extracted():
    payload = b"powershell http://webp.example/stage"
    chunk = b"XMP " + len(payload).to_bytes(4, "little") + payload
    if len(payload) & 1:
        chunk += b"\x00"
    body = b"WEBP" + chunk
    carrier = b"RIFF" + len(body).to_bytes(4, "little") + body
    extracted = SteganographyAnalyzer().analyze(carrier)
    assert any(name.startswith("steg_webp_xmp") and data == payload for name, data in extracted)


def test_tiff_ascii_tag_payload_is_extracted():
    payload = b"https://tiff.example/payload\x00"
    ifd_offset = 8
    payload_offset = ifd_offset + 2 + 12 + 4
    entry = struct.pack("<HHII", 0x010E, 2, len(payload), payload_offset)
    carrier = b"II*\x00" + struct.pack("<I", ifd_offset)
    carrier += struct.pack("<H", 1) + entry + b"\x00\x00\x00\x00" + payload
    extracted = SteganographyAnalyzer().analyze(carrier)
    assert any(name.startswith("steg_tiff_tag_010e") for name, _ in extracted)


def test_mp3_id3_private_payload_is_extracted():
    payload = b"MZ http://mp3.example/dropper"
    frame = b"PRIV" + len(payload).to_bytes(4, "big") + b"\x00\x00" + payload
    carrier = b"ID3\x03\x00\x00" + _synchsafe(len(frame)) + frame
    extracted = SteganographyAnalyzer().analyze(carrier)
    assert any(name.startswith("steg_mp3_priv") and data == payload for name, data in extracted)


def test_mp4_uuid_payload_is_extracted():
    ftyp = (12).to_bytes(4, "big") + b"ftyp" + b"isom"
    payload = b"PK\x03\x04 http://mp4.example/archive"
    uuid = (8 + len(payload)).to_bytes(4, "big") + b"uuid" + payload
    extracted = SteganographyAnalyzer().analyze(ftyp + uuid)
    assert any(name.startswith("steg_mp4_uuid") and data == payload for name, data in extracted)


def test_malformed_media_never_raises_or_extracts():
    analyzer = SteganographyAnalyzer()
    malformed = b"\x89PNG\r\n\x1a\n" + (0xFFFFFFFF).to_bytes(4, "big") + b"IDAT"
    assert analyzer.analyze(malformed) == []


def test_config_can_disable_steganography_analyzer(tmp_path):
    cfg = Config(tmp_path / "does-not-exist.json")
    analyzers = dict(cfg.get("analyzers"))
    analyzers["steganography"] = False
    cfg.set("analyzers", analyzers)
    assert all(
        analyzer.name != "Steganography" for analyzer in TitanEngine(cfg).analyzers
    )
