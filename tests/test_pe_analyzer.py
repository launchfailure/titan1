import struct
import json

from titan_decoder.core.analyzers.base import PEAnalyzer
from titan_decoder.core.engine import TitanEngine


def _build_pe(magic, opt_header_size, tail=b""):
    # DOS header: MZ + padding + e_lfanew=64
    mz = b"MZ" + b"\x00" * 58 + struct.pack("<I", 64)
    machine = 0x8664 if magic == 0x20B else 0x14C
    coff = struct.pack(
        "<HHIIIHH", machine, 4, 0x600D1234, 0, 0, opt_header_size, 0x0022
    )
    # Standard optional-header common fields (24 bytes):
    # magic, major/minor linker, code/init/uninit sizes, entry point, base of code.
    opt = (
        struct.pack("<HBBIIIII", magic, 14, 29, 0x1000, 0x800, 0, 0x1500, 0x1000) + tail
    )
    return mz + b"PE\x00\x00" + coff + opt


def _build_dotnet_pe() -> bytes:
    pe_offset = 0x80
    optional_size = 0xE0
    section_rva = 0x2000
    section_raw = 0x200
    cli_rva = section_rva
    metadata_rva = section_rva + 0x100
    resources_rva = section_rva + 0x340

    optional = bytearray(optional_size)
    struct.pack_into("<H", optional, 0, 0x10B)
    struct.pack_into("<I", optional, 16, section_rva)
    struct.pack_into("<I", optional, 28, 0x400000)
    struct.pack_into("<I", optional, 92, 16)
    struct.pack_into("<II", optional, 96 + 14 * 8, cli_rva, 72)

    version = b"v4.0.30319\x00"
    metadata = bytearray(struct.pack("<IHHII", 0x424A5342, 1, 1, 0, len(version)))
    metadata += version
    metadata += b"\x00" * (-len(metadata) % 4)
    metadata += struct.pack("<HH", 0, 4)

    def stream_header(offset: int, size: int, name: bytes) -> bytes:
        value = bytearray(struct.pack("<II", offset, size) + name + b"\x00")
        value += b"\x00" * (-len(value) % 4)
        return bytes(value)

    metadata += stream_header(0x100, 128, b"#~")
    metadata += stream_header(0x180, 96, b"#Strings")
    metadata += stream_header(0x1E0, 32, b"#Blob")
    metadata += stream_header(0x200, 16, b"#GUID")
    metadata += b"\x00" * (0x100 - len(metadata))

    strings = bytearray(b"\x00")

    def add_string(value: str) -> int:
        index = len(strings)
        strings.extend(value.encode("utf-8") + b"\x00")
        return index

    module_name = add_string("ManagedFixture")
    assembly_name = add_string("AssemblyFixture")
    culture = add_string("en-US")
    reference_name = add_string("Dependency")
    resource_name = add_string("config.json")
    external_resource_name = add_string("external.bin")

    blobs = bytearray(b"\x00")

    def add_blob(value: bytes) -> int:
        assert len(value) < 0x80
        index = len(blobs)
        blobs.extend(bytes([len(value)]) + value)
        return index

    public_key = add_blob(b"\x01\x02\x03\x04")
    public_key_token = add_blob(bytes.fromhex("aabbccddeeff0011"))
    reference_hash = add_blob(bytes.fromhex("deadbeef"))

    valid_tables = (1 << 0) | (1 << 32) | (1 << 35) | (1 << 40)
    tables = bytearray(
        struct.pack(
            "<IBBBBQQIIII",
            0,
            2,
            0,
            0,
            1,
            valid_tables,
            0,
            1,
            1,
            1,
            2,
        )
    )
    tables += struct.pack("<HHHHH", 0, module_name, 1, 0, 0)
    tables += struct.pack(
        "<IHHHHIHHH",
        0x8004,
        1,
        2,
        3,
        4,
        1,
        public_key,
        assembly_name,
        culture,
    )
    tables += struct.pack(
        "<HHHHIHHHH",
        5,
        6,
        7,
        8,
        0,
        public_key_token,
        reference_name,
        0,
        reference_hash,
    )
    tables += struct.pack("<IIHH", 0, 1, resource_name, 0)
    tables += struct.pack("<IIHH", 0, 2, external_resource_name, 5)
    metadata += tables.ljust(128, b"\x00")
    metadata += bytes(strings).ljust(96, b"\x00")
    metadata += bytes(blobs).ljust(32, b"\x00")
    metadata += bytes.fromhex("00112233445566778899aabbccddeeff")

    dos = bytearray(pe_offset)
    dos[:2] = b"MZ"
    struct.pack_into("<I", dos, 60, pe_offset)
    coff = struct.pack("<HHIIIHH", 0x14C, 1, 0, 0, 0, optional_size, 0x0022)
    section = bytearray(40)
    section[:8] = b".text\x00\x00\x00"
    struct.pack_into(
        "<IIIIIIHHI",
        section,
        8,
        0x400,
        section_rva,
        0x400,
        section_raw,
        0,
        0,
        0,
        0,
        0x60000020,
    )
    output = bytearray(0x600)
    headers = bytes(dos) + b"PE\x00\x00" + coff + bytes(optional) + bytes(section)
    output[: len(headers)] = headers
    struct.pack_into(
        "<IHHIIII",
        output,
        section_raw,
        72,
        2,
        5,
        metadata_rva,
        len(metadata),
        0x00000009,
        0x06000001,
    )
    struct.pack_into("<II", output, section_raw + 24, resources_rva, 64)
    struct.pack_into("<II", output, section_raw + 32, section_rva + 0xC0, 32)
    output[section_raw + 0x100 : section_raw + 0x100 + len(metadata)] = metadata
    resource_payload = b'{"url":"https://managed.example/stage"}'
    struct.pack_into("<I", output, section_raw + 0x340, len(resource_payload))
    output[section_raw + 0x344 : section_raw + 0x344 + len(resource_payload)] = (
        resource_payload
    )
    return bytes(output)


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
        0x10B,
        0xE0,
        tail=struct.pack("<I", 0) + struct.pack("<I", 0x400000) + b"\x00" * 200,
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


def test_pe_extracts_bounded_dotnet_runtime_and_metadata_structure():
    artifacts = dict(PEAnalyzer().analyze(_build_dotnet_pe()))
    dotnet = json.loads(artifacts["pe_metadata.json"])["dotnet"]

    assert dotnet["present"] is True
    assert dotnet["valid"] is True
    assert dotnet["runtime_version"] == "2.5"
    assert dotnet["metadata_version_string"] == "v4.0.30319"
    assert dotnet["flags"] == {
        "raw": "0x00000009",
        "il_only": True,
        "requires_32_bit": False,
        "strong_name_signed": True,
        "native_entry_point": False,
        "prefers_32_bit": False,
    }
    assert dotnet["entry_point"] == {
        "kind": "metadata_token",
        "value": "0x06000001",
    }
    assert [stream["name"] for stream in dotnet["streams"]] == [
        "#~",
        "#Strings",
        "#Blob",
        "#GUID",
    ]
    assert dotnet["table_row_counts"] == {
        "Assembly": 1,
        "AssemblyRef": 1,
        "ManifestResource": 2,
        "Module": 1,
    }
    assert dotnet["module"] == {
        "name": "ManagedFixture",
        "mvid": "00112233445566778899aabbccddeeff",
        "mvid_index": 1,
    }
    assert dotnet["assembly"] == {
        "name": "AssemblyFixture",
        "version": "1.2.3.4",
        "culture": "en-US",
        "flags": "0x00000001",
        "hash_algorithm": "sha1",
        "public_key": {
            "size": 4,
            "sha256": "9f64a747e1b97f131fabb6b447296c9b6f0201e79fb3c5356e6c77e89b6a806a",
            "preview_hex": "01020304",
        },
    }
    assert dotnet["assembly_references"] == [
        {
            "row": 1,
            "name": "Dependency",
            "version": "5.6.7.8",
            "culture": "neutral",
            "flags": "0x00000000",
            "public_key_or_token": "aabbccddeeff0011",
            "hash": "deadbeef",
        }
    ]
    assert dotnet["manifest_resources"] == [
        {
            "row": 1,
            "name": "config.json",
            "offset": 0,
            "visibility": "public",
            "implementation": "embedded",
            "embedded_data": {
                "size": 39,
                "file_offset": 1348,
                "range_valid": True,
                "sha256": "7b65b1097804336db1ef072b1296ce4dff58e817eb8beadc600c09d109589f9d",
                "artifact": "dotnet_resource_001_config.json",
                "stored": True,
            },
        },
        {
            "row": 2,
            "name": "external.bin",
            "offset": 0,
            "visibility": "private",
            "implementation": {"table": "AssemblyRef", "row": 1},
        },
    ]
    assert dotnet["string_heap_preview"] == [
        "ManagedFixture",
        "AssemblyFixture",
        "en-US",
        "Dependency",
        "config.json",
        "external.bin",
    ]
    assert dotnet["strong_name_signature"]["range_valid"] is True
    assert artifacts["dotnet_resource_001_config.json"] == (
        b'{"url":"https://managed.example/stage"}'
    )

    report = TitanEngine().run_analysis(_build_dotnet_pe())
    assert "https://managed.example/stage" in report["iocs"]["urls"]
    assert any(
        node.get("artifact_name") == "dotnet_resource_001_config.json"
        for node in report["nodes"]
    )


def test_pe_dotnet_metadata_corruption_fails_closed_with_bounded_diagnostics():
    malformed = bytearray(_build_dotnet_pe())
    malformed[0x300:0x304] = b"NOPE"
    dotnet = PEAnalyzer()._extract_pe_metadata(bytes(malformed))["dotnet"]

    assert dotnet["present"] is True
    assert dotnet["valid"] is False
    assert dotnet["anomalies"] == ["invalid_metadata_signature"]


def test_pe_dotnet_rejects_truncated_tables_and_invalid_embedded_resources():
    truncated_table = bytearray(_build_dotnet_pe())
    struct.pack_into("<I", truncated_table, 0x300 + 0x100 + 32, 2000)
    dotnet = PEAnalyzer()._extract_pe_metadata(bytes(truncated_table))["dotnet"]
    assert dotnet["valid"] is False
    assert "truncated_metadata_table:35" in dotnet["anomalies"]

    invalid_resource = bytearray(_build_dotnet_pe())
    struct.pack_into("<I", invalid_resource, 0x540, 4096)
    dotnet = PEAnalyzer()._extract_pe_metadata(bytes(invalid_resource))["dotnet"]
    assert dotnet["valid"] is False
    assert "invalid_manifest_resource_range:1" in dotnet["anomalies"]
    assert dotnet["manifest_resources"][0]["embedded_data"] == {
        "size": 4096,
        "file_offset": 1348,
        "range_valid": False,
        "sha256": None,
    }


def test_pe_identifies_structurally_valid_nsis_overlay_header():
    nsis_header = struct.pack(
        "<7I",
        0x05,
        0xDEADBEEF,
        0x6C6C754E,
        0x74666F73,
        0x74736E49,
        64,
        156,
    )
    metadata = PEAnalyzer()._extract_pe_metadata(
        _build_dotnet_pe() + nsis_header + b"N" * 128
    )

    assert metadata["installer"] == {
        "overlay_offset": 0x600,
        "overlay_size": 156,
        "scan_bytes": 156,
        "scan_truncated": False,
        "formats": [
            {
                "family": "NSIS",
                "offset": 0x600,
                "header_length": 64,
                "following_data_length": 156,
                "range_valid": True,
                "flags": {
                    "raw": "0x00000005",
                    "uninstaller": True,
                    "silent": False,
                    "no_crc": True,
                    "force_crc": False,
                },
            }
        ],
    }


def test_pe_identifies_inno_data_version_and_rejects_installer_near_misses():
    identifier = b"Inno Setup Setup Data (6.4.0.1) (u)"
    metadata = PEAnalyzer()._extract_pe_metadata(
        _build_dotnet_pe() + b"prefix" + identifier + b"\x00"
    )
    assert metadata["installer"]["formats"] == [
        {
            "family": "Inno Setup",
            "offset": 0x606,
            "identifier": identifier.decode("ascii"),
            "data_format_version": "6.4.0.1",
            "unicode": True,
        }
    ]

    invalid_nsis = struct.pack(
        "<7I",
        0x10,
        0xDEADBEEF,
        0x6C6C754E,
        0x74666F73,
        0x74736E49,
        64,
        28,
    )
    near_miss = _build_dotnet_pe() + invalid_nsis + b"Inno Setup Setup Data (version)"
    assert "installer" not in PEAnalyzer()._extract_pe_metadata(near_miss)
