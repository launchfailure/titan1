import binascii
import json
import struct
import uuid

from titan_decoder.core.analyzers.executable_formats import VirtualDiskAnalyzer
from titan_decoder.core.engine import TitanEngine


def _wrap_fixed_vhd(disk: bytearray) -> bytes:
    footer = bytearray(512)
    footer[:8] = b"conectix"
    struct.pack_into(">IIQ", footer, 8, 2, 0x00010000, 0xFFFFFFFFFFFFFFFF)
    footer[28:32] = b"TITN"
    struct.pack_into(">I", footer, 32, 0x00010000)
    footer[36:40] = b"Wi2k"
    struct.pack_into(">QQ", footer, 40, len(disk), len(disk))
    struct.pack_into(">II", footer, 56, (1 << 16) | (16 << 8) | 63, 2)
    footer[68:84] = uuid.UUID("12345678-1234-5678-9abc-def012345678").bytes
    checksum = VirtualDiskAnalyzer._vhd_checksum(bytes(footer))
    struct.pack_into(">I", footer, 64, checksum)
    return bytes(disk + footer)


def _build_fixed_vhd(partition_payload: bytes = b"VHD partition payload") -> bytes:
    disk = bytearray(1024)
    disk[446] = 0x80
    disk[450] = 0x07
    struct.pack_into("<II", disk, 454, 1, 1)
    disk[510:512] = b"\x55\xaa"
    disk[512 : 512 + len(partition_payload)] = partition_payload[:512]
    return _wrap_fixed_vhd(disk)


def _build_fixed_gpt_vhd(partition_payload: bytes = b"GPT partition payload") -> bytes:
    disk = bytearray(6 * 512)
    disk[446 + 4] = 0xEE
    struct.pack_into("<II", disk, 446 + 8, 1, 5)
    disk[510:512] = b"\x55\xaa"

    entries = bytearray(512)
    entries[:16] = uuid.UUID("ebd0a0a2-b9e5-4433-87c0-68b6b72699c7").bytes_le
    entries[16:32] = uuid.UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").bytes_le
    struct.pack_into("<QQQ", entries, 32, 3, 3, 0)
    name = "Evidence".encode("utf-16-le")
    entries[56 : 56 + len(name)] = name
    disk[2 * 512 : 3 * 512] = entries

    header = bytearray(512)
    header[:8] = b"EFI PART"
    struct.pack_into("<II", header, 8, 0x00010000, 92)
    struct.pack_into("<QQQQ", header, 24, 1, 5, 3, 4)
    header[56:72] = uuid.UUID("11111111-2222-3333-4444-555555555555").bytes_le
    struct.pack_into("<QII", header, 72, 2, 4, 128)
    struct.pack_into("<I", header, 88, binascii.crc32(entries) & 0xFFFFFFFF)
    prepared = bytearray(header[:92])
    prepared[16:20] = b"\x00" * 4
    struct.pack_into("<I", header, 16, binascii.crc32(prepared) & 0xFFFFFFFF)
    disk[512:1024] = header
    disk[3 * 512 : 3 * 512 + len(partition_payload)] = partition_payload[:512]
    return _wrap_fixed_vhd(disk)


def _vhdx_header(sequence: int) -> bytes:
    header = bytearray(4096)
    header[:4] = b"head"
    struct.pack_into("<Q", header, 8, sequence)
    header[16:32] = uuid.UUID(int=sequence).bytes_le
    header[32:48] = uuid.UUID(int=sequence + 10).bytes_le
    struct.pack_into("<HHIQ", header, 64, 0, 1, 0, 0)
    checksum = VirtualDiskAnalyzer._crc32c(bytes(header))
    struct.pack_into("<I", header, 4, checksum)
    return bytes(header)


def _vhdx_region_table() -> bytes:
    table = bytearray(65536)
    table[:4] = b"regi"
    struct.pack_into("<I", table, 8, 2)
    entries = (
        ("2dc27766-f623-4200-9d64-115e9bfd4a08", 1 << 20),
        ("8b7ca206-4790-4b9a-b8fe-575f050f886e", 2 << 20),
    )
    for index, (guid, offset) in enumerate(entries):
        at = 16 + index * 32
        table[at : at + 16] = uuid.UUID(guid).bytes_le
        struct.pack_into("<QII", table, at + 16, offset, 1 << 20, 1)
    checksum = VirtualDiskAnalyzer._crc32c(bytes(table))
    struct.pack_into("<I", table, 4, checksum)
    return bytes(table)


def _vhdx_metadata_region() -> bytes:
    region = bytearray(1 << 20)
    region[:8] = b"metadata"
    struct.pack_into("<H", region, 10, 5)
    definitions = (
        (
            "caa16737-fa36-4d43-b3b6-33f0aa44e76b",
            struct.pack("<II", 1 << 20, 1),
            4,
        ),
        (
            "2fa54224-cd1b-4876-b211-5dbed83bf4b8",
            struct.pack("<Q", 1 << 20),
            6,
        ),
        (
            "beca12ab-b2e6-4523-93ef-c309e000c746",
            uuid.UUID("99999999-8888-7777-6666-555555555555").bytes_le,
            6,
        ),
        (
            "8141bf1d-a96f-4709-ba47-f233a8faab5f",
            struct.pack("<I", 512),
            6,
        ),
        (
            "cda348c7-445d-4471-9cc9-e9885251c556",
            struct.pack("<I", 4096),
            6,
        ),
    )
    item_offset = 65536
    for index, (guid, value, flags) in enumerate(definitions):
        at = 32 + index * 32
        region[at : at + 16] = uuid.UUID(guid).bytes_le
        struct.pack_into("<IIII", region, at + 16, item_offset, len(value), flags, 0)
        region[item_offset : item_offset + len(value)] = value
        item_offset += len(value)
    return bytes(region)


def _build_vhdx() -> bytes:
    data = bytearray(4 << 20)
    data[:8] = b"vhdxfile"
    creator = "Titan1 fixture".encode("utf-16-le")
    data[8 : 8 + len(creator)] = creator
    data[64 << 10 : (64 << 10) + 4096] = _vhdx_header(1)
    data[128 << 10 : (128 << 10) + 4096] = _vhdx_header(2)
    table = _vhdx_region_table()
    data[192 << 10 : 256 << 10] = table
    data[256 << 10 : 320 << 10] = table
    data[2 << 20 : 3 << 20] = _vhdx_metadata_region()
    struct.pack_into("<Q", data, 1 << 20, (3 << 20) | 6)
    payload = bytearray(1 << 20)
    payload[446] = 0x80
    payload[450] = 0x07
    struct.pack_into("<II", payload, 454, 1, 1)
    payload[510:512] = b"\x55\xaa"
    payload[512:544] = b"https://vhdx.example/stage\x00\x00\x00\x00\x00\x00"
    data[3 << 20 : 4 << 20] = payload
    return bytes(data)


def _artifacts(data: bytes, config=None) -> dict[str, bytes]:
    return dict(VirtualDiskAnalyzer(config).analyze(data))


def test_fixed_vhd_footer_and_partition_are_parsed_and_extracted():
    artifacts = _artifacts(_build_fixed_vhd(b"https://disk.example/stage"))
    metadata = json.loads(artifacts["virtual_disk_metadata.json"])

    assert metadata["file_type"] == "VHD"
    assert metadata["footer_valid"] is True
    assert metadata["disk_type"] == "fixed"
    assert metadata["partition_table"] == {
        "anomalies": [],
        "scheme": "MBR",
        "valid": True,
    }
    assert metadata["unique_id"] == "12345678-1234-5678-9abc-def012345678"
    assert metadata["partitions"] == [
        {
            "bootable": True,
            "offset": 512,
            "range_valid": True,
            "sector_count": 1,
            "size": 512,
            "slot": 1,
            "start_lba": 1,
            "type": "0x07",
        }
    ]
    assert artifacts["disk_partition_001.bin"].startswith(b"https://disk.example/stage")

    report = TitanEngine().run_analysis(_build_fixed_vhd(b"https://disk.example/stage"))
    assert "https://disk.example/stage" in report["iocs"]["urls"]


def test_vhd_invalid_checksum_fails_closed_without_partition_extraction():
    data = bytearray(_build_fixed_vhd())
    data[-448] ^= 0x01
    artifacts = _artifacts(bytes(data))
    metadata = json.loads(artifacts["virtual_disk_metadata.json"])

    assert metadata["footer_valid"] is False
    assert metadata["anomalies"] == ["invalid_footer_checksum"]
    assert "disk_partition_001.bin" not in artifacts


def test_vhd_partition_extraction_honors_item_bound():
    artifacts = _artifacts(_build_fixed_vhd(), {"max_structured_artifact_size": 128})
    metadata = json.loads(artifacts["virtual_disk_metadata.json"])

    assert metadata["partitions"][0]["range_valid"] is True
    assert metadata["partitions_extracted"] == 0
    assert list(artifacts) == ["virtual_disk_metadata.json"]


def test_fixed_vhd_gpt_header_entries_and_partition_are_validated():
    artifacts = _artifacts(_build_fixed_gpt_vhd(b"https://gpt.example/stage"))
    metadata = json.loads(artifacts["virtual_disk_metadata.json"])

    assert metadata["partition_table"] == {
        "alternate_lba": 5,
        "anomalies": [],
        "disk_guid": "11111111-2222-3333-4444-555555555555",
        "entries_scanned": 4,
        "entries_truncated": False,
        "entry_array_crc_valid": True,
        "entry_count": 4,
        "entry_lba": 2,
        "entry_size": 128,
        "first_usable_lba": 3,
        "header_crc_valid": True,
        "last_usable_lba": 4,
        "revision": "0x00010000",
        "scheme": "GPT",
        "valid": True,
    }
    assert metadata["partitions"][0]["name"] == "Evidence"
    assert metadata["partitions"][0]["type_guid"] == (
        "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7"
    )
    assert artifacts["disk_partition_001.bin"].startswith(b"https://gpt.example/stage")


def test_fixed_vhd_gpt_crc_corruption_fails_closed():
    data = bytearray(_build_fixed_gpt_vhd())
    data[2 * 512 + 100] ^= 0x01
    metadata = json.loads(_artifacts(bytes(data))["virtual_disk_metadata.json"])

    assert metadata["partition_table"]["valid"] is False
    assert metadata["partition_table"]["anomalies"] == ["invalid_gpt_entry_array_crc"]
    assert metadata["partitions"] == []


def test_vhdx_headers_and_region_tables_are_checksum_validated():
    artifacts = _artifacts(_build_vhdx())
    metadata = json.loads(artifacts["virtual_disk_metadata.json"])

    assert metadata["file_type"] == "VHDX"
    assert metadata["creator"] == "Titan1 fixture"
    assert metadata["current_header_offset"] == 128 << 10
    assert [header["valid"] for header in metadata["headers"]] == [True, True]
    assert [table["valid"] for table in metadata["region_tables"]] == [True, True]
    assert [region["name"] for region in metadata["region_tables"][0]["regions"]] == [
        "bat",
        "metadata",
    ]
    assert metadata["metadata"]["values"] == {
        "file_parameters": {
            "block_size": 1 << 20,
            "has_parent": False,
            "leave_blocks_allocated": True,
            "valid": True,
        },
        "logical_sector_size": 512,
        "physical_sector_size": 4096,
        "virtual_disk_id": "99999999-8888-7777-6666-555555555555",
        "virtual_disk_size": 1 << 20,
    }
    assert metadata["metadata"]["valid"] is True
    assert metadata["bat"]["reconstructed"] is True
    assert metadata["bat"]["state_counts"] == {"fully_present": 1}
    assert metadata["partition_table"]["scheme"] == "MBR"
    assert metadata["partitions"][0]["range_valid"] is True
    assert artifacts["virtual_disk_payload.bin"][512:538] == (
        b"https://vhdx.example/stage"
    )
    assert artifacts["disk_partition_001.bin"].startswith(b"https://vhdx.example/stage")
    assert metadata["anomalies"] == []

    report = TitanEngine().run_analysis(_build_vhdx())
    assert "https://vhdx.example/stage" in report["iocs"]["urls"]


def test_vhdx_corrupt_newer_header_falls_back_to_older_valid_copy():
    data = bytearray(_build_vhdx())
    data[(128 << 10) + 100] ^= 0x01
    metadata = json.loads(_artifacts(bytes(data))["virtual_disk_metadata.json"])

    assert metadata["current_header_offset"] == 64 << 10
    assert metadata["headers"][1]["anomalies"] == ["invalid_header_checksum"]


def test_vhdx_signature_only_is_bounded_malformed_metadata():
    analyzer = VirtualDiskAnalyzer()
    data = b"vhdxfile" + b"\x00" * 1024

    assert analyzer.can_analyze(data) is True
    metadata = json.loads(dict(analyzer.analyze(data))["virtual_disk_metadata.json"])
    assert metadata["anomalies"] == [
        "no_valid_header",
        "no_valid_region_table",
        "missing_metadata_region",
        "missing_bat_region",
    ]


def test_vhdx_metadata_invalid_required_item_range_fails_closed():
    data = bytearray(_build_vhdx())
    metadata_region = 2 << 20
    struct.pack_into("<I", data, metadata_region + 32 + 16, (1 << 20) - 4)
    metadata = json.loads(_artifacts(bytes(data))["virtual_disk_metadata.json"])

    assert metadata["metadata"]["valid"] is False
    assert "metadata_item_range_invalid" in metadata["metadata"]["anomalies"]
    assert "missing_metadata_item:file_parameters" in metadata["metadata"]["anomalies"]
    assert metadata["anomalies"] == ["invalid_metadata_region"]


def test_vhdx_bat_payload_range_failure_prevents_reconstruction():
    data = bytearray(_build_vhdx())
    struct.pack_into("<Q", data, 1 << 20, (5 << 20) | 6)
    metadata = json.loads(_artifacts(bytes(data))["virtual_disk_metadata.json"])

    assert metadata["bat"]["valid"] is False
    assert metadata["bat"]["anomalies"] == ["payload_block_range_invalid"]
    assert metadata["bat"]["reconstructed"] is False
    assert metadata["anomalies"] == ["invalid_bat_region"]


def test_vhdx_reconstruction_honors_artifact_size_bound():
    artifacts = _artifacts(
        _build_vhdx(), {"max_structured_artifact_size": (1 << 20) - 1}
    )
    metadata = json.loads(artifacts["virtual_disk_metadata.json"])

    assert metadata["bat"]["valid"] is True
    assert metadata["bat"]["reconstructable_within_limits"] is False
    assert metadata["bat"]["reconstructed"] is False
    assert metadata["artifacts"] == []
    assert list(artifacts) == ["virtual_disk_metadata.json"]


def test_virtual_disk_rejects_signature_lookalikes():
    analyzer = VirtualDiskAnalyzer()

    assert analyzer.can_analyze(b"vhdxfilE" + b"\x00" * 1024) is False
    assert analyzer.can_analyze(b"conectix" + b"\x00" * 503) is False
