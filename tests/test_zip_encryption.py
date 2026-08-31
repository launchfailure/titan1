import binascii
import struct

from titan_decoder.core.analyzers.base import ZipAnalyzer


def _crc32_byte(value: int, byte: int) -> int:
    value ^= byte
    for _ in range(8):
        value = (value >> 1) ^ (0xEDB88320 if value & 1 else 0)
    return value & 0xFFFFFFFF


def _zipcrypto_encrypt(data: bytes, password: bytes) -> bytes:
    keys = [0x12345678, 0x23456789, 0x34567890]

    def update(byte: int) -> None:
        keys[0] = _crc32_byte(keys[0], byte)
        keys[1] = (keys[1] + (keys[0] & 0xFF)) & 0xFFFFFFFF
        keys[1] = (keys[1] * 134775813 + 1) & 0xFFFFFFFF
        keys[2] = _crc32_byte(keys[2], (keys[1] >> 24) & 0xFF)

    for byte in password:
        update(byte)

    encrypted = bytearray()
    for byte in data:
        mask_seed = (keys[2] & 0xFFFF) | 2
        encrypted.append(byte ^ ((mask_seed * (mask_seed ^ 1)) >> 8) & 0xFF)
        update(byte)
    return bytes(encrypted)


def _encrypted_zip(
    content: bytes, password: bytes = b"infected", filename: bytes = b"sample.txt"
) -> bytes:
    """Build one deterministic traditional-ZipCrypto entry for stdlib tests."""
    crc = binascii.crc32(content) & 0xFFFFFFFF
    encryption_header = b"Titan1-test" + bytes([crc >> 24])
    encrypted = _zipcrypto_encrypt(encryption_header + content, password)
    compressed_size = len(encrypted)
    flags = 0x1
    method = 0
    local = struct.pack(
        "<IHHHHHIIIHH",
        0x04034B50,
        20,
        flags,
        method,
        0,
        0,
        crc,
        compressed_size,
        len(content),
        len(filename),
        0,
    ) + filename + encrypted
    central = struct.pack(
        "<IHHHHHHIIIHHHHHII",
        0x02014B50,
        20,
        20,
        flags,
        method,
        0,
        0,
        crc,
        compressed_size,
        len(content),
        len(filename),
        0,
        0,
        0,
        0,
        0,
        0,
    ) + filename
    eocd = struct.pack(
        "<IHHHHIIH",
        0x06054B50,
        0,
        0,
        1,
        1,
        len(central),
        len(local),
        0,
    )
    return local + central + eocd


def test_default_infected_password_extracts_encrypted_zip():
    data = _encrypted_zip(b"beacon https://encrypted.example/stage")

    assert ZipAnalyzer().analyze(data) == [
        ("sample.txt", b"beacon https://encrypted.example/stage")
    ]


def test_configured_password_extracts_encrypted_zip():
    data = _encrypted_zip(b"private", password=b"case-password")

    assert ZipAnalyzer({"zip_passwords": ["wrong", "case-password"]}).analyze(data) == [
        ("sample.txt", b"private")
    ]


def test_wrong_or_disabled_password_skips_encrypted_entry():
    data = _encrypted_zip(b"private", password=b"case-password")

    assert ZipAnalyzer({"zip_passwords": ["wrong"]}).analyze(data) == []
    assert ZipAnalyzer({"zip_passwords": []}).analyze(data) == []


def test_password_allowlist_is_bounded_and_validated():
    analyzer = ZipAnalyzer(
        {"zip_passwords": ["", 7, *(f"p{i}" for i in range(12)), "x" * 129]}
    )

    assert analyzer.passwords == tuple(f"p{i}".encode() for i in range(6))
