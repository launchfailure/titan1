"""Bounded corpus tests for Mach-O and DEX structural analyzers."""

import json
import struct

from titan_decoder.config import Config
from titan_decoder.core.analyzers.executable_formats import DexAnalyzer, MachOAnalyzer
from titan_decoder.core.engine import TitanEngine


def _macho64() -> bytes:
    section_data = b"Mach-O payload http://macho.example/x"
    section_offset = 32 + 152 + 56
    header = b"\xcf\xfa\xed\xfe" + struct.pack(
        "<IIIIIII", 0x01000007, 3, 2, 2, 208, 0x200000, 0
    )
    segment = struct.pack("<II16sQQQQIIII", 0x19, 152, b"__TEXT", 0x100000000, 0x1000, 0, len(section_data), 7, 5, 1, 0)
    section = struct.pack("<16s16sQQIIIIIIII", b"__text", b"__TEXT", 0x100000F50, len(section_data), section_offset, 4, 0, 0, 0x80000400, 0, 0, 0)
    dylib_name = b"/usr/lib/libSystem.B.dylib\x00"
    dylib = struct.pack("<IIIIII", 0xC, 56, 24, 0, 0, 0) + dylib_name.ljust(32, b"\x00")
    return header + segment + section + dylib + section_data


def _dex(strings: list[bytes]) -> bytes:
    ids_offset = 112
    data_offset = ids_offset + len(strings) * 4
    items = bytearray()
    offsets = []
    for value in strings:
        offsets.append(data_offset + len(items))
        items.extend(bytes((len(value),)) + value + b"\x00")
    file_size = data_offset + len(items)
    header = bytearray(112)
    header[:8] = b"dex\n035\x00"
    struct.pack_into("<III", header, 32, file_size, 112, 0x12345678)
    struct.pack_into("<II", header, 56, len(strings), ids_offset)
    struct.pack_into("<II", header, 104, len(items), data_offset)
    return bytes(header) + b"".join(struct.pack("<I", item) for item in offsets) + bytes(items)


def test_macho_extracts_load_commands_sections_and_dylibs():
    analyzer = MachOAnalyzer()
    data = _macho64()
    assert analyzer.can_analyze(data)
    result = json.loads(analyzer.analyze(data)[0][1])
    assert result["bits"] == 64
    assert result["cpu_type"] == "x86_64"
    assert result["dylibs"] == ["/usr/lib/libSystem.B.dylib"]
    assert result["sections"][0]["name"] == "__text"
    assert result["sections"][0]["size"] == 37


def test_macho_rejects_truncated_and_impossible_command_regions():
    analyzer = MachOAnalyzer()
    assert not analyzer.can_analyze(b"\xcf\xfa\xed\xfe")
    malformed = bytearray(_macho64())
    struct.pack_into("<I", malformed, 20, len(malformed) + 1)
    assert analyzer.analyze(bytes(malformed)) == []


def test_dex_extracts_bounded_strings_and_table_metadata():
    analyzer = DexAnalyzer()
    data = _dex([b"Lcom/example/Main;", b"https://dex.example/gate"])
    artifacts = dict(analyzer.analyze(data))
    metadata = json.loads(artifacts["dex_metadata.json"])
    assert metadata["version"] == "035"
    assert metadata["tables"]["string"]["count"] == 2
    assert artifacts["dex_strings.txt"] == b"Lcom/example/Main;\nhttps://dex.example/gate"


def test_dex_rejects_bad_endian_tag_and_out_of_range_table():
    analyzer = DexAnalyzer()
    bad_endian = bytearray(_dex([b"hello"]))
    struct.pack_into("<I", bad_endian, 40, 0)
    assert analyzer.analyze(bytes(bad_endian)) == []
    bad_table = bytearray(_dex([b"hello"]))
    struct.pack_into("<I", bad_table, 60, len(bad_table) + 10)
    assert analyzer.analyze(bytes(bad_table)) == []


def test_engine_registers_new_executable_analyzers_and_extracts_dex_ioc():
    engine = TitanEngine(Config())
    assert {analyzer.name for analyzer in engine.analyzers} >= {"DEX", "Mach-O"}
    report = engine.run_analysis(_dex([b"https://dex.example/gate"]))
    assert "https://dex.example/gate" in report["iocs"]["urls"]
