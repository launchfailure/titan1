"""Bounded, dependency-free steganography and media-payload extraction.

The analyzer deliberately performs *static extraction only*.  Recovered bytes
are returned to :class:`TitanEngine` as child artifacts, where the normal
decoder, IOC, detection, and assurance pipelines inspect them.  Nothing in
this module writes, opens, imports, or executes a recovered payload.

Supported carriers:

* PNG: trailing data, suspicious text/private chunks, and 8-bit LSB payloads
* BMP: trailing data and uncompressed 24/32-bit pixel LSB payloads
* WAV: RIFF trailing data and PCM sample LSB payloads
* JPEG/GIF: trailing data and suspicious comment/application metadata
* AVI/other RIFF containers: bytes beyond the declared RIFF boundary

LSB recovery accepts a length-framed ``TITANSTEG\0`` stream, a recognized file
signature near the start of the bitstream, or suspicious NUL-terminated text.
Those strict acceptance rules keep ordinary pixel/audio noise from becoming a
false hidden-payload finding.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import math
import re
import struct
import zlib
from typing import Any, Iterable, List, Tuple

from .base import Analyzer
from ...decoders.base import Decoder


_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
_LSB_FRAME = b"TITANSTEG\x00"
_PADDING = b"\x00\xff \t\r\n"
_KNOWN_PNG_CHUNKS = {
    b"IHDR",
    b"PLTE",
    b"IDAT",
    b"IEND",
    b"tRNS",
    b"cHRM",
    b"gAMA",
    b"iCCP",
    b"sBIT",
    b"sRGB",
    b"tEXt",
    b"zTXt",
    b"iTXt",
    b"bKGD",
    b"hIST",
    b"pHYs",
    b"sPLT",
    b"tIME",
    b"eXIf",
}
_MAGICS = (
    (b"MZ", ".exe"),
    (b"\x7fELF", ".elf"),
    (b"PK\x03\x04", ".zip"),
    (b"%PDF-", ".pdf"),
    (b"\x1f\x8b\x08", ".gz"),
    (b"BZh", ".bz2"),
    (b"\xfd7zXZ\x00", ".xz"),
    (b"Rar!\x1a\x07", ".rar"),
    (b"#!/", ".sh"),
)
_ACTIVE_HINTS = (
    b"http://",
    b"https://",
    b"powershell",
    b"cmd.exe",
    b"wscript",
    b"cscript",
    b"javascript:",
    b"<script",
    b"fromcharcode",
    b"downloadstring",
    b"invoke-expression",
    b"#!/bin/",
)


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for value in data:
        counts[value] += 1
    size = len(data)
    return -sum((count / size) * math.log2(count / size) for count in counts if count)


def _bounded_zlib(data: bytes, limit: int) -> bytes | None:
    """Return a complete zlib stream without ever producing over ``limit``."""
    try:
        decoder = zlib.decompressobj()
        output = decoder.decompress(data, limit + 1)
        if len(output) > limit or decoder.unconsumed_tail:
            return None
        output += decoder.flush(limit + 1 - len(output))
        if len(output) > limit or not decoder.eof:
            return None
        return output
    except (ValueError, zlib.error):
        return None


def _looks_base64(data: bytes) -> bool:
    compact = b"".join(data.split())
    if len(compact) < 64 or len(compact) % 4 == 1:
        return False
    if re.fullmatch(rb"[A-Za-z0-9+/=_-]+", compact) is None:
        return False
    try:
        base64.b64decode(compact + b"=" * (-len(compact) % 4), validate=False)
        return True
    except (binascii.Error, ValueError):
        return False


def _is_suspicious(data: bytes) -> bool:
    if len(data) < 4:
        return False
    sample = data[:1_000_000]
    lowered = sample.lower()
    if any(magic in sample[:256] for magic, _ in _MAGICS):
        return True
    if any(hint in lowered for hint in _ACTIVE_HINTS):
        return True
    if _looks_base64(sample):
        return True
    return len(sample) >= 128 and _entropy(sample) >= 7.25


def _meaningful_trailer(data: bytes) -> bytes:
    """Ignore padding-only tails while preserving payload bytes byte-for-byte."""
    if len(data) < 4 or not data.strip(_PADDING):
        return b""
    return data


def _payload_extension(data: bytes) -> str:
    for magic, extension in _MAGICS:
        if data.startswith(magic):
            return extension
    if (
        data
        and sum(32 <= value < 127 or value in (9, 10, 13) for value in data) / len(data)
        >= 0.9
    ):
        return ".txt"
    return ".bin"


def _pack_lsb_stream(values: Iterable[int], limit: int) -> tuple[bytes, bytes]:
    """Pack carrier LSBs in both common bit orders, with a hard byte cap."""
    msb = bytearray()
    lsb = bytearray()
    msb_value = 0
    lsb_value = 0
    bit_index = 0
    for value in values:
        bit = value & 1
        msb_value = (msb_value << 1) | bit
        lsb_value |= bit << bit_index
        bit_index += 1
        if bit_index == 8:
            msb.append(msb_value)
            lsb.append(lsb_value)
            if len(msb) >= limit:
                break
            msb_value = 0
            lsb_value = 0
            bit_index = 0
    return bytes(msb), bytes(lsb)


def _recover_lsb_payload(streams: Iterable[bytes], limit: int) -> bytes:
    """Recover only strongly framed or recognizable content from LSB bytes."""
    for stream in streams:
        marker_at = stream[:512].find(_LSB_FRAME)
        if marker_at >= 0:
            length_at = marker_at + len(_LSB_FRAME)
            if length_at + 4 <= len(stream):
                raw_length = stream[length_at : length_at + 4]
                for byte_order in ("big", "little"):
                    payload_length = int.from_bytes(raw_length, byte_order)
                    payload_at = length_at + 4
                    if (
                        0 < payload_length <= limit
                        and payload_at + payload_length <= len(stream)
                    ):
                        return stream[payload_at : payload_at + payload_length]

        for magic, _ in _MAGICS:
            offset = stream[:64].find(magic)
            if offset >= 0:
                # A two-byte MZ collision occurs too often in natural LSB noise
                # to be evidence by itself. Require a structurally valid PE
                # signature when the candidate is not explicitly framed.
                if magic == b"MZ":
                    candidate = stream[offset:]
                    if len(candidate) < 64:
                        continue
                    pe_offset = int.from_bytes(candidate[60:64], "little")
                    if (
                        pe_offset < 64
                        or pe_offset + 4 > len(candidate)
                        or candidate[pe_offset : pe_offset + 4] != b"PE\x00\x00"
                    ):
                        continue
                return stream[offset : offset + limit].rstrip(b"\x00")

        terminator = stream.find(b"\x00", 16, min(len(stream), limit))
        if terminator >= 16:
            candidate = stream[:terminator]
            printable = sum(
                32 <= value < 127 or value in (9, 10, 13) for value in candidate
            ) / len(candidate)
            if printable >= 0.95 and _is_suspicious(candidate):
                return candidate
    return b""


class SteganographyAnalyzer(Analyzer):
    """Extract suspicious hidden content from common image/media carriers."""

    def __init__(self, config: dict[str, Any] | None = None):
        config = config or {}
        self.max_artifacts = int(config.get("max_media_artifacts", 8))
        self.max_total_size = int(config.get("max_media_total_size", 8 * 1024 * 1024))
        self.max_artifact_size = int(
            config.get("max_media_artifact_size", 4 * 1024 * 1024)
        )
        self.max_lsb_carrier_bytes = int(
            config.get("max_lsb_carrier_bytes", 4 * 1024 * 1024)
        )
        self.max_lsb_output_size = int(config.get("max_lsb_output_size", 1024 * 1024))

    @property
    def name(self) -> str:
        return "Steganography"

    def can_analyze(self, data: bytes) -> bool:
        return bool(
            data.startswith(_PNG_SIGNATURE)
            or data.startswith((b"BM", b"\xff\xd8", b"GIF87a", b"GIF89a"))
            or (len(data) >= 12 and data[:4] == b"RIFF")
        )

    def analyze(self, data: bytes) -> List[Tuple[str, bytes]]:
        found: list[tuple[str, bytes]] = []
        if data.startswith(_PNG_SIGNATURE):
            candidates = self._analyze_png(data)
        elif data.startswith(b"BM"):
            candidates = self._analyze_bmp(data)
        elif data.startswith(b"\xff\xd8"):
            candidates = self._analyze_jpeg(data)
        elif data.startswith((b"GIF87a", b"GIF89a")):
            candidates = self._analyze_gif(data)
        elif len(data) >= 12 and data[:4] == b"RIFF":
            candidates = self._analyze_riff(data)
        else:
            candidates = []

        total = 0
        hashes: set[bytes] = set()
        for name, payload in candidates:
            if not payload or len(found) >= self.max_artifacts:
                break
            payload = payload[: self.max_artifact_size]
            if total + len(payload) > self.max_total_size:
                break
            identity = hashlib.sha256(payload).digest()
            if identity in hashes:
                continue
            hashes.add(identity)
            found.append((name, payload))
            total += len(payload)
        return found

    def _trailer(
        self, data: bytes, end: int | None, carrier: str
    ) -> list[tuple[str, bytes]]:
        if end is None or end < 0 or end > len(data):
            return []
        trailer = _meaningful_trailer(data[end:])
        if not trailer:
            return []
        extension = _payload_extension(trailer)
        return [(f"steg_{carrier}_appended_payload{extension}", trailer)]

    def _analyze_png(self, data: bytes) -> list[tuple[str, bytes]]:
        found: list[tuple[str, bytes]] = []
        position = len(_PNG_SIGNATURE)
        end: int | None = None
        ihdr: bytes | None = None
        idat = bytearray()

        while position + 12 <= len(data):
            length = int.from_bytes(data[position : position + 4], "big")
            chunk_type = data[position + 4 : position + 8]
            chunk_end = position + 12 + length
            if chunk_end > len(data):
                return []
            payload = data[position + 8 : position + 8 + length]

            if chunk_type == b"IHDR":
                ihdr = payload
            elif (
                chunk_type == b"IDAT"
                and len(idat) + length <= self.max_lsb_carrier_bytes
            ):
                idat.extend(payload)
            elif chunk_type in {b"tEXt", b"zTXt", b"iTXt"}:
                decoded = self._decode_png_text(chunk_type, payload)
                if decoded and _is_suspicious(decoded):
                    label = chunk_type.decode("ascii", errors="replace")
                    found.append((f"steg_png_{label}_payload.txt", decoded))
            elif chunk_type not in _KNOWN_PNG_CHUNKS and _is_suspicious(payload):
                label = re.sub(rb"[^A-Za-z0-9]", b"_", chunk_type).decode("ascii")
                found.append(
                    (
                        f"steg_png_private_{label}{_payload_extension(payload)}",
                        payload,
                    )
                )

            position = chunk_end
            if chunk_type == b"IEND":
                end = chunk_end
                break

        found.extend(self._trailer(data, end, "png"))
        lsb = self._png_lsb(ihdr, bytes(idat))
        if lsb:
            found.append((f"steg_png_lsb_payload{_payload_extension(lsb)}", lsb))
        return found

    def _decode_png_text(self, kind: bytes, payload: bytes) -> bytes:
        try:
            if kind == b"tEXt":
                return payload.split(b"\x00", 1)[-1][: self.max_artifact_size]
            if kind == b"zTXt":
                _, encoded = payload.split(b"\x00", 1)
                if not encoded or encoded[0] != 0:
                    return b""
                return _bounded_zlib(encoded[1:], self.max_artifact_size) or b""

            # iTXt: keyword NUL, compression flag/method, language NUL,
            # translated keyword NUL, then UTF-8 text (possibly compressed).
            _, rest = payload.split(b"\x00", 1)
            if len(rest) < 2:
                return b""
            compressed = rest[0] == 1
            rest = rest[2:]
            _, rest = rest.split(b"\x00", 1)
            _, text = rest.split(b"\x00", 1)
            if compressed:
                return _bounded_zlib(text, self.max_artifact_size) or b""
            return text[: self.max_artifact_size]
        except (ValueError, IndexError):
            return b""

    def _png_lsb(self, ihdr: bytes | None, compressed: bytes) -> bytes:
        if ihdr is None or len(ihdr) != 13 or not compressed:
            return b""
        width, height = struct.unpack(">II", ihdr[:8])
        bit_depth, color_type, compression, filtering, interlace = ihdr[8:13]
        channels = {0: 1, 2: 3, 4: 2, 6: 4}.get(color_type)
        if (
            not channels
            or bit_depth != 8
            or compression != 0
            or filtering != 0
            or interlace != 0
            or width == 0
            or height == 0
        ):
            return b""
        row_bytes = width * channels
        expected = (row_bytes + 1) * height
        if expected > self.max_lsb_carrier_bytes:
            return b""
        raw = _bounded_zlib(compressed, expected)
        if raw is None or len(raw) != expected:
            return b""

        prior = bytearray(row_bytes)
        pixels = bytearray()
        offset = 0
        for _ in range(height):
            filter_type = raw[offset]
            scan = bytearray(raw[offset + 1 : offset + 1 + row_bytes])
            offset += row_bytes + 1
            if filter_type > 4:
                return b""
            for index in range(row_bytes):
                left = scan[index - channels] if index >= channels else 0
                up = prior[index]
                upper_left = prior[index - channels] if index >= channels else 0
                if filter_type == 1:
                    scan[index] = (scan[index] + left) & 0xFF
                elif filter_type == 2:
                    scan[index] = (scan[index] + up) & 0xFF
                elif filter_type == 3:
                    scan[index] = (scan[index] + ((left + up) // 2)) & 0xFF
                elif filter_type == 4:
                    scan[index] = (
                        scan[index] + self._paeth(left, up, upper_left)
                    ) & 0xFF
            pixels.extend(scan)
            prior = scan

        color_channels = 1 if color_type in {0, 4} else 3
        carrier = (
            pixels[index]
            for index in range(len(pixels))
            if index % channels < color_channels
        )
        streams = _pack_lsb_stream(carrier, self.max_lsb_output_size + 526)
        return _recover_lsb_payload(streams, self.max_lsb_output_size)

    @staticmethod
    def _paeth(left: int, up: int, upper_left: int) -> int:
        estimate = left + up - upper_left
        left_distance = abs(estimate - left)
        up_distance = abs(estimate - up)
        upper_left_distance = abs(estimate - upper_left)
        if left_distance <= up_distance and left_distance <= upper_left_distance:
            return left
        if up_distance <= upper_left_distance:
            return up
        return upper_left

    def _analyze_bmp(self, data: bytes) -> list[tuple[str, bytes]]:
        if len(data) < 54:
            return []
        declared_size = int.from_bytes(data[2:6], "little")
        pixel_offset = int.from_bytes(data[10:14], "little")
        dib_size = int.from_bytes(data[14:18], "little")
        found = self._trailer(
            data, declared_size if declared_size >= 14 else None, "bmp"
        )
        if dib_size < 40 or len(data) < 14 + dib_size:
            return found
        width = int.from_bytes(data[18:22], "little", signed=True)
        height = int.from_bytes(data[22:26], "little", signed=True)
        planes = int.from_bytes(data[26:28], "little")
        bits_per_pixel = int.from_bytes(data[28:30], "little")
        compression = int.from_bytes(data[30:34], "little")
        if (
            width <= 0
            or height == 0
            or planes != 1
            or bits_per_pixel not in {24, 32}
            or compression != 0
        ):
            return found
        rows = abs(height)
        pixel_bytes = bits_per_pixel // 8
        row_size = ((width * bits_per_pixel + 31) // 32) * 4
        carrier_size = row_size * rows
        if (
            carrier_size > self.max_lsb_carrier_bytes
            or pixel_offset + carrier_size > len(data)
        ):
            return found

        def carrier() -> Iterable[int]:
            for row in range(rows):
                start = pixel_offset + row * row_size
                for column in range(width):
                    pixel = start + column * pixel_bytes
                    yield data[pixel]
                    yield data[pixel + 1]
                    yield data[pixel + 2]

        streams = _pack_lsb_stream(carrier(), self.max_lsb_output_size + 526)
        lsb = _recover_lsb_payload(streams, self.max_lsb_output_size)
        if lsb:
            found.append((f"steg_bmp_lsb_payload{_payload_extension(lsb)}", lsb))
        return found

    def _analyze_riff(self, data: bytes) -> list[tuple[str, bytes]]:
        if len(data) < 12:
            return []
        declared_end = int.from_bytes(data[4:8], "little") + 8
        carrier = data[8:12].decode("ascii", errors="replace").lower()
        found = self._trailer(
            data, declared_end if declared_end >= 12 else None, carrier or "riff"
        )
        if data[8:12] != b"WAVE":
            return found

        position = 12
        fmt: bytes | None = None
        samples: bytes | None = None
        while position + 8 <= min(declared_end, len(data)):
            chunk_type = data[position : position + 4]
            length = int.from_bytes(data[position + 4 : position + 8], "little")
            payload_at = position + 8
            chunk_end = payload_at + length
            if chunk_end > min(declared_end, len(data)):
                break
            payload = data[payload_at:chunk_end]
            if chunk_type == b"fmt ":
                fmt = payload
            elif chunk_type == b"data":
                samples = payload
            position = chunk_end + (length & 1)

        if not fmt or len(fmt) < 16 or samples is None:
            return found
        audio_format, channels, _, _, block_align, bits_per_sample = struct.unpack(
            "<HHIIHH", fmt[:16]
        )
        sample_width = (bits_per_sample + 7) // 8
        if (
            audio_format != 1
            or channels == 0
            or sample_width not in {1, 2, 3, 4}
            or block_align < channels * sample_width
            or len(samples) > self.max_lsb_carrier_bytes
        ):
            return found
        carrier_values = (
            samples[index]
            for index in range(0, len(samples) - sample_width + 1, sample_width)
        )
        streams = _pack_lsb_stream(carrier_values, self.max_lsb_output_size + 526)
        lsb = _recover_lsb_payload(streams, self.max_lsb_output_size)
        if lsb:
            found.append((f"steg_wav_lsb_payload{_payload_extension(lsb)}", lsb))
        return found

    def _analyze_jpeg(self, data: bytes) -> list[tuple[str, bytes]]:
        position = 2
        comments: list[tuple[str, bytes]] = []
        end: int | None = None
        while position < len(data):
            if data[position] != 0xFF:
                position += 1
                continue
            while position < len(data) and data[position] == 0xFF:
                position += 1
            if position >= len(data):
                break
            marker = data[position]
            position += 1
            if marker == 0xD9:
                end = position
                break
            if marker in {0x01, *range(0xD0, 0xD9)}:
                continue
            if position + 2 > len(data):
                break
            length = int.from_bytes(data[position : position + 2], "big")
            if length < 2 or position + length > len(data):
                break
            payload = data[position + 2 : position + length]
            if (marker == 0xFE or 0xE0 <= marker <= 0xEF) and _is_suspicious(payload):
                comments.append(
                    (
                        f"steg_jpeg_marker_{marker:02x}{_payload_extension(payload)}",
                        payload,
                    )
                )
            position += length
            if marker == 0xDA:  # Entropy-coded scan; find the next real marker.
                while position + 1 < len(data):
                    if data[position] != 0xFF:
                        position += 1
                        continue
                    following = data[position + 1]
                    if following == 0x00 or 0xD0 <= following <= 0xD7:
                        position += 2
                        continue
                    break
        comments.extend(self._trailer(data, end, "jpeg"))
        return comments

    def _analyze_gif(self, data: bytes) -> list[tuple[str, bytes]]:
        if len(data) < 13:
            return []
        packed = data[10]
        position = 13
        if packed & 0x80:
            position += 3 * (2 ** ((packed & 0x07) + 1))
        comments: list[tuple[str, bytes]] = []
        end: int | None = None

        def sub_blocks(start: int) -> tuple[bytes, int] | None:
            output = bytearray()
            at = start
            while at < len(data):
                size = data[at]
                at += 1
                if size == 0:
                    return bytes(output), at
                if at + size > len(data):
                    return None
                if len(output) <= self.max_artifact_size:
                    output.extend(data[at : at + size])
                at += size
            return None

        while position < len(data):
            introducer = data[position]
            if introducer == 0x3B:
                end = position + 1
                break
            if introducer == 0x21 and position + 2 <= len(data):
                label = data[position + 1]
                result = sub_blocks(position + 2)
                if result is None:
                    break
                payload, position = result
                if label in {0xFE, 0xFF} and _is_suspicious(payload):
                    comments.append(
                        (
                            f"steg_gif_extension_{label:02x}{_payload_extension(payload)}",
                            payload,
                        )
                    )
                continue
            if introducer == 0x2C and position + 10 <= len(data):
                descriptor_packed = data[position + 9]
                position += 10
                if descriptor_packed & 0x80:
                    position += 3 * (2 ** ((descriptor_packed & 0x07) + 1))
                if position >= len(data):
                    break
                position += 1  # LZW minimum code size
                result = sub_blocks(position)
                if result is None:
                    break
                _, position = result
                continue
            break
        comments.extend(self._trailer(data, end, "gif"))
        return comments


class MediaPayloadDecoder(Decoder):
    """Manual workbench decoder that returns the first recovered media payload."""

    def __init__(self, max_output: int = 4 * 1024 * 1024):
        self.analyzer = SteganographyAnalyzer(
            {
                "max_media_artifacts": 1,
                "max_media_total_size": max_output,
                "max_media_artifact_size": max_output,
                "max_lsb_output_size": max_output,
            }
        )

    @property
    def name(self) -> str:
        return "SteganographyMedia"

    def can_decode(self, data: bytes) -> bool:
        return self.analyzer.can_analyze(data)

    def decode(self, data: bytes) -> tuple[bytes, bool]:
        if not self.can_decode(data):
            return data, False
        extracted = self.analyzer.analyze(data)
        if not extracted:
            return data, False
        return extracted[0][1], True
