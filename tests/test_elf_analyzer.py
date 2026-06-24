import struct

from titan_decoder.core.analyzers.base import ELFAnalyzer


def _make_elf(entry, machine, etype, phnum, shnum, cls64=True, little_endian=True):
    endian = "<" if little_endian else ">"
    e_ident = (
        bytes([0x7F])
        + b"ELF"
        + bytes([2 if cls64 else 1, 1 if little_endian else 2, 1, 0])
        + b"\x00" * 8
    )
    if cls64:
        rest = struct.pack(
            endian + "HHIQQQIHHHHHH",
            etype, machine, 1, entry, 0x40, 0x2000, 0, 64, 56, phnum, 64, shnum, 29,
        )
    else:
        rest = struct.pack(
            endian + "HHIIIIIHHHHHH",
            etype, machine, 1, entry, 0x40, 0x2000, 0, 52, 32, phnum, 40, shnum, 28,
        )
    return e_ident + rest + b"\x00" * 200


def test_elf64_little_endian():
    md = ELFAnalyzer()._extract_elf_metadata(
        _make_elf(0x401000, 0x3E, 2, 9, 30, cls64=True, little_endian=True)
    )
    assert md["class"] == "64-bit"
    assert md["machine_type"] == "x86-64"
    assert md["object_type"] == "Executable"
    assert md["num_program_headers"] == 9
    assert md["num_section_headers"] == 30
    assert md["entry_point"] == "0x0000000000401000"


def test_elf64_big_endian():
    md = ELFAnalyzer()._extract_elf_metadata(
        _make_elf(0x400ABC, 0xB7, 3, 5, 12, cls64=True, little_endian=False)
    )
    assert md["data_encoding"] == "Big endian"
    assert md["machine_type"] == "AArch64"
    assert md["num_program_headers"] == 5
    assert md["num_section_headers"] == 12


def test_elf64_high_entry_point():
    md = ELFAnalyzer()._extract_elf_metadata(
        _make_elf(0x7FFF12345678, 0x3E, 2, 11, 40, cls64=True, little_endian=True)
    )
    # A >32-bit entry point must survive (was truncated before the fix).
    assert md["entry_point"] == "0x00007fff12345678"
    assert md["num_program_headers"] == 11


def test_elf32_little_endian():
    md = ELFAnalyzer()._extract_elf_metadata(
        _make_elf(0x8048000, 0x03, 2, 7, 25, cls64=False, little_endian=True)
    )
    assert md["class"] == "32-bit"
    assert md["machine_type"] == "x86"
    assert md["num_program_headers"] == 7
    assert md["num_section_headers"] == 25
    assert md["entry_point"] == "0x08048000"
