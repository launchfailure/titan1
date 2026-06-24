import struct

from titan_decoder.core.analyzers.base import PEAnalyzer


def _build_pe(magic, opt_header_size, tail=b""):
    # DOS header: MZ + padding + e_lfanew=64
    mz = b"MZ" + b"\x00" * 58 + struct.pack("<I", 64)
    machine = 0x8664 if magic == 0x20B else 0x14C
    coff = struct.pack(
        "<HHIIIHH", machine, 4, 0x600D1234, 0, 0, opt_header_size, 0x0022
    )
    # Standard optional-header common fields (24 bytes):
    # magic, major/minor linker, code/init/uninit sizes, entry point, base of code.
    opt = struct.pack(
        "<HBBIIIII", magic, 14, 29, 0x1000, 0x800, 0, 0x1500, 0x1000
    ) + tail
    return mz + b"PE\x00\x00" + coff + opt


def test_pe32plus_metadata():
    pe = _build_pe(0x20B, 0xF0, tail=struct.pack("<Q", 0x140000000) + b"\x00" * 200)
    md = PEAnalyzer()._extract_pe_metadata(pe)
    assert "error" not in md
    assert md["machine_type"] == "x64"
    assert md["magic"] == "PE32+"
    assert md["num_sections"] == 4
    assert md["entry_point"] == "0x00001500"
    assert md["image_base"] == "0x0000000140000000"


def test_pe32_metadata():
    pe = _build_pe(
        0x10B, 0xE0, tail=struct.pack("<I", 0) + struct.pack("<I", 0x400000) + b"\x00" * 200
    )
    md = PEAnalyzer()._extract_pe_metadata(pe)
    assert "error" not in md
    assert md["machine_type"] == "x86"
    assert md["magic"] == "PE32"
    assert md["image_base"] == "0x00400000"


def test_truncated_pe_keeps_core_metadata():
    # Optional header declared but no image-base bytes present: parsing should
    # still yield core metadata and simply omit image_base (no error).
    pe = _build_pe(0x20B, 0xF0)
    md = PEAnalyzer()._extract_pe_metadata(pe)
    assert "error" not in md
    assert md["machine_type"] == "x64"
    assert md["entry_point"] == "0x00001500"
    assert "image_base" not in md


def test_pe_analyze_returns_metadata_json():
    pe = _build_pe(0x20B, 0xF0, tail=struct.pack("<Q", 0x140000000) + b"\x00" * 200)
    result = PEAnalyzer().analyze(pe)
    assert len(result) == 1
    name, content = result[0]
    assert name == "pe_metadata.json"
    assert b"PE32+" in content
