"""Bounded structural analyzers for additional executable formats."""

from __future__ import annotations

import json
import struct
from typing import Any

from .base import Analyzer
from ...utils.helpers import entropy


class MachOAnalyzer(Analyzer):
    """Parse thin 32/64-bit Mach-O headers, load commands, and sections."""

    _MAGICS = {
        b"\xce\xfa\xed\xfe": ("<", 32),
        b"\xcf\xfa\xed\xfe": ("<", 64),
        b"\xfe\xed\xfa\xce": (">", 32),
        b"\xfe\xed\xfa\xcf": (">", 64),
    }
    _CPU_TYPES = {
        7: "x86",
        0x01000007: "x86_64",
        12: "arm",
        0x0100000C: "arm64",
        18: "powerpc",
        0x01000012: "powerpc64",
    }
    _FILE_TYPES = {1: "object", 2: "executable", 6: "dylib", 8: "bundle"}
    _DYLIB_COMMANDS = {0xC, 0x18, 0x1F, 0x80000018, 0x8000001F}
    _MAX_COMMANDS = 2048
    _MAX_SECTIONS = 1024

    @property
    def name(self) -> str:
        return "Mach-O"

    @property
    def metadata_artifact_names(self) -> frozenset:
        return frozenset({"macho_metadata.json"})

    def can_analyze(self, data: bytes) -> bool:
        return len(data) >= 28 and data[:4] in self._MAGICS

    @staticmethod
    def _cstring(raw: bytes) -> str:
        return raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace")

    def analyze(self, data: bytes) -> list[tuple[str, bytes]]:
        metadata = self._parse(data)
        if metadata is None:
            return []
        return [("macho_metadata.json", json.dumps(metadata, indent=2).encode())]

    def _parse(self, data: bytes) -> dict[str, Any] | None:
        layout = self._MAGICS.get(data[:4])
        if layout is None:
            return None
        endian, bits = layout
        header_size = 32 if bits == 64 else 28
        if len(data) < header_size:
            return None
        cpu_type, cpu_subtype, file_type, ncmds, commands_size, flags = (
            struct.unpack_from(f"{endian}IIIIII", data, 4)
        )
        if ncmds > self._MAX_COMMANDS or commands_size > len(data) - header_size:
            return None
        commands_end = header_size + commands_size
        cursor = header_size
        sections: list[dict[str, Any]] = []
        dylibs: list[str] = []
        entry_offset: int | None = None
        uuid: str | None = None
        anomalies: list[str] = []
        for _ in range(ncmds):
            if cursor + 8 > commands_end:
                return None
            command, command_size = struct.unpack_from(f"{endian}II", data, cursor)
            if command_size < 8 or command_size > commands_end - cursor:
                return None
            if command in (1, 0x19):
                is_64 = command == 0x19
                segment_header = 72 if is_64 else 56
                section_size = 80 if is_64 else 68
                if command_size < segment_header:
                    return None
                nsects_at = cursor + (64 if is_64 else 48)
                nsects = struct.unpack_from(f"{endian}I", data, nsects_at)[0]
                if nsects > self._MAX_SECTIONS - len(sections):
                    return None
                if segment_header + nsects * section_size > command_size:
                    return None
                for index in range(nsects):
                    at = cursor + segment_header + index * section_size
                    section_name = self._cstring(data[at : at + 16])
                    segment_name = self._cstring(data[at + 16 : at + 32])
                    if is_64:
                        address, size, offset, _align, _reloc, _nreloc, sec_flags = (
                            struct.unpack_from(f"{endian}QQIIIII", data, at + 32)
                        )
                    else:
                        address, size, offset, _align, _reloc, _nreloc, sec_flags = (
                            struct.unpack_from(f"{endian}IIIIIII", data, at + 32)
                        )
                    raw = (
                        data[offset : offset + size]
                        if offset <= len(data) and size <= len(data) - offset
                        else b""
                    )
                    if size and not raw:
                        anomalies.append(
                            f"invalid_section_range:{segment_name},{section_name}"
                        )
                    sections.append(
                        {
                            "segment": segment_name,
                            "name": section_name,
                            "address": f"0x{address:x}",
                            "offset": offset,
                            "size": size,
                            "entropy": round(entropy(raw), 4) if raw else 0.0,
                            "flags": f"0x{sec_flags:08x}",
                        }
                    )
            elif command in self._DYLIB_COMMANDS and command_size >= 24:
                name_offset = struct.unpack_from(f"{endian}I", data, cursor + 8)[0]
                if 24 <= name_offset < command_size:
                    name = self._cstring(
                        data[cursor + name_offset : cursor + command_size]
                    )
                    if name:
                        dylibs.append(name)
            elif command == 0x80000028 and command_size >= 24:
                entry_offset = struct.unpack_from(f"{endian}Q", data, cursor + 8)[0]
            elif command == 0x1B and command_size >= 24:
                raw_uuid = data[cursor + 8 : cursor + 24].hex()
                uuid = "-".join(
                    (
                        raw_uuid[:8],
                        raw_uuid[8:12],
                        raw_uuid[12:16],
                        raw_uuid[16:20],
                        raw_uuid[20:],
                    )
                )
            cursor += command_size
        if cursor != commands_end:
            anomalies.append("load_command_padding")
        return {
            "file_type": "Mach-O",
            "bits": bits,
            "endianness": "little" if endian == "<" else "big",
            "cpu_type": self._CPU_TYPES.get(cpu_type, f"unknown:0x{cpu_type:08x}"),
            "cpu_subtype": f"0x{cpu_subtype:08x}",
            "macho_type": self._FILE_TYPES.get(file_type, f"unknown:{file_type}"),
            "flags": f"0x{flags:08x}",
            "load_command_count": ncmds,
            "entry_offset": entry_offset,
            "uuid": uuid,
            "dylibs": sorted(set(dylibs), key=str.lower),
            "sections": sections,
            "anomalies": sorted(set(anomalies)),
        }


class DexAnalyzer(Analyzer):
    """Parse DEX headers and a bounded subset of the string table."""

    _MAX_TABLE_ITEMS = 1_000_000
    _MAX_STRINGS = 4096
    _MAX_STRING_BYTES = 4096
    _MAX_TOTAL_STRING_BYTES = 2 * 1024 * 1024

    @property
    def name(self) -> str:
        return "DEX"

    @property
    def metadata_artifact_names(self) -> frozenset:
        return frozenset({"dex_metadata.json"})

    def can_analyze(self, data: bytes) -> bool:
        return len(data) >= 112 and data[:4] == b"dex\n" and data[7] == 0

    def analyze(self, data: bytes) -> list[tuple[str, bytes]]:
        parsed = self._parse(data)
        if parsed is None:
            return []
        metadata, strings = parsed
        artifacts = [("dex_metadata.json", json.dumps(metadata, indent=2).encode())]
        if strings:
            artifacts.append(("dex_strings.txt", "\n".join(strings).encode("utf-8")))
        return artifacts

    @staticmethod
    def _uleb128(data: bytes, offset: int) -> tuple[int, int] | None:
        value = 0
        for index in range(5):
            if offset + index >= len(data):
                return None
            byte = data[offset + index]
            value |= (byte & 0x7F) << (index * 7)
            if not byte & 0x80:
                return value, offset + index + 1
        return None

    def _parse(self, data: bytes) -> tuple[dict[str, Any], list[str]] | None:
        if not self.can_analyze(data):
            return None
        version = data[4:7].decode("ascii", errors="replace")
        file_size, header_size, endian_tag = struct.unpack_from("<III", data, 32)
        if (
            file_size < 112
            or file_size > len(data)
            or header_size != 112
            or endian_tag != 0x12345678
        ):
            return None
        table_names = ("string", "type", "proto", "field", "method", "class")
        tables: dict[str, dict[str, int]] = {}
        for index, name in enumerate(table_names):
            count, offset = struct.unpack_from("<II", data, 56 + index * 8)
            if count > self._MAX_TABLE_ITEMS or (
                count and not 112 <= offset < file_size
            ):
                return None
            tables[name] = {"count": count, "offset": offset}
        string_count = tables["string"]["count"]
        string_offset = tables["string"]["offset"]
        if string_count and (string_count > (file_size - string_offset) // 4):
            return None
        strings: list[str] = []
        total = 0
        for index in range(min(string_count, self._MAX_STRINGS)):
            item_offset = struct.unpack_from("<I", data, string_offset + index * 4)[0]
            prefix = self._uleb128(data, item_offset)
            if prefix is None:
                continue
            _utf16_length, start = prefix
            end = data.find(
                b"\x00", start, min(file_size, start + self._MAX_STRING_BYTES + 1)
            )
            if end < 0:
                continue
            raw = data[start:end]
            total += len(raw)
            if total > self._MAX_TOTAL_STRING_BYTES:
                break
            text = raw.decode("utf-8", errors="replace").strip()
            if text:
                strings.append(text)
        metadata = {
            "file_type": "DEX",
            "version": version,
            "file_size": file_size,
            "checksum_adler32": f"0x{struct.unpack_from('<I', data, 8)[0]:08x}",
            "signature_sha1": data[12:32].hex(),
            "tables": tables,
            "strings_emitted": len(strings),
            "strings_truncated": string_count > len(strings),
        }
        return metadata, strings
