from abc import ABC, abstractmethod
from typing import Tuple
import base64
import bz2
import lzma
import zlib
import binascii
import re

from ..utils.helpers import (
    looks_like_base64,
    looks_like_gzip,
    looks_like_bz2,
    looks_like_hex,
)


# Cap on decompressed output to defend against decompression bombs: a few KB of
# bz2/gzip/lzma can expand to many GB. This mirrors the size limits the archive
# (ZIP/TAR) analyzers already enforce. The engine overrides this per-decoder
# from config (max_data_size).
DEFAULT_MAX_DECOMPRESSED_SIZE = 100 * 1024 * 1024  # 100 MB


def _bounded_decompress(make_decompressor, data: bytes, max_output: int) -> bytes:
    """Decompress with an output cap to defend against decompression bombs.

    ``make_decompressor`` is a zero-arg factory returning a fresh incremental
    decompressor (zlib/bz2/lzma style) exposing ``decompress(data, max_length)``,
    ``.eof`` and ``.unused_data``. Concatenated streams (e.g. multi-member gzip)
    are handled by creating a new decompressor per stream. ``decompress`` returns
    at most ``max_length`` bytes and buffers the rest, so peak memory stays
    bounded. Raises ValueError if the total output would exceed ``max_output``.
    """
    result = bytearray()
    remaining = data
    while remaining:
        decompressor = make_decompressor()
        # Allow one byte past the remaining budget so overflow is detectable.
        budget = max_output - len(result) + 1
        result += decompressor.decompress(remaining, budget)
        if len(result) > max_output or not decompressor.eof:
            raise ValueError("decompressed output exceeds maximum allowed size")
        remaining = decompressor.unused_data
    return bytes(result)


class Decoder(ABC):
    """Base class for all decoders."""

    @abstractmethod
    def can_decode(self, data: bytes) -> bool:
        """Check if this decoder can handle the data."""
        pass

    @abstractmethod
    def decode(self, data: bytes) -> Tuple[bytes, bool]:
        """Decode the data. Return (decoded_data, success)."""
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the decoder."""
        pass


class Base64Decoder(Decoder):
    """Base64 decoder with multiline support."""

    def can_decode(self, data: bytes) -> bool:
        return looks_like_base64(data)

    def decode(self, data: bytes) -> Tuple[bytes, bool]:
        try:
            # Handle multiline
            lines = data.splitlines()
            decoded_parts = []
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                if looks_like_base64(line.encode()):
                    decoded_parts.append(base64.b64decode(line))
                else:
                    decoded_parts.append(line.encode())
            return b"\n".join(decoded_parts), True
        except Exception:
            return data, False

    @property
    def name(self) -> str:
        return "Base64"


class RecursiveBase64Decoder(Decoder):
    """Recursive Base64 decoder."""

    def __init__(self, max_depth: int = 3):
        self.max_depth = max_depth

    def can_decode(self, data: bytes) -> bool:
        return looks_like_base64(data)

    def decode(self, data: bytes) -> Tuple[bytes, bool]:
        depth = 0
        current = data
        while depth < self.max_depth and looks_like_base64(current):
            try:
                current = base64.b64decode(current)
                depth += 1
            except Exception:
                break
        return current, depth > 0

    @property
    def name(self) -> str:
        return "RecursiveBase64"


class GzipDecoder(Decoder):
    """Gzip decompressor."""

    def __init__(self, max_output_size: int = DEFAULT_MAX_DECOMPRESSED_SIZE):
        self.max_output_size = max_output_size

    def can_decode(self, data: bytes) -> bool:
        return looks_like_gzip(data)

    def decode(self, data: bytes) -> Tuple[bytes, bool]:
        try:
            # wbits=31 selects the gzip header/format.
            return _bounded_decompress(
                lambda: zlib.decompressobj(31), data, self.max_output_size
            ), True
        except Exception:
            return data, False

    @property
    def name(self) -> str:
        return "Gzip"


class Bz2Decoder(Decoder):
    """Bz2 decompressor."""

    def __init__(self, max_output_size: int = DEFAULT_MAX_DECOMPRESSED_SIZE):
        self.max_output_size = max_output_size

    def can_decode(self, data: bytes) -> bool:
        return looks_like_bz2(data)

    def decode(self, data: bytes) -> Tuple[bytes, bool]:
        try:
            return _bounded_decompress(
                bz2.BZ2Decompressor, data, self.max_output_size
            ), True
        except Exception:
            return data, False

    @property
    def name(self) -> str:
        return "Bz2"


class LzmaDecoder(Decoder):
    """LZMA/XZ decompressor."""

    def __init__(self, max_output_size: int = DEFAULT_MAX_DECOMPRESSED_SIZE):
        self.max_output_size = max_output_size

    def can_decode(self, data: bytes) -> bool:
        return data.startswith(b"\xfd7zXZ") or data.startswith(b"\x5d\x00\x00")

    def decode(self, data: bytes) -> Tuple[bytes, bool]:
        try:
            return _bounded_decompress(
                lzma.LZMADecompressor, data, self.max_output_size
            ), True
        except Exception:
            return data, False

    @property
    def name(self) -> str:
        return "LZMA"


class ZlibDecoder(Decoder):
    """ZLIB decompressor."""

    def __init__(self, max_output_size: int = DEFAULT_MAX_DECOMPRESSED_SIZE):
        self.max_output_size = max_output_size

    def can_decode(self, data: bytes) -> bool:
        # ZLIB compressed data typically starts with compression method
        # This is a heuristic - ZLIB doesn't have a fixed header like GZIP
        if len(data) < 2:
            return False
        # Check for ZLIB header (compression method and flags)
        # First byte: Compression method (8 = deflate)
        # Second byte: Flags
        compression_method = data[0] & 0x0F
        return compression_method == 8  # Deflate compression

    def decode(self, data: bytes) -> Tuple[bytes, bool]:
        try:
            return _bounded_decompress(
                zlib.decompressobj, data, self.max_output_size
            ), True
        except Exception:
            return data, False

    @property
    def name(self) -> str:
        return "ZLIB"


class HexDecoder(Decoder):
    """Hex decoder."""

    def can_decode(self, data: bytes) -> bool:
        return looks_like_hex(data)

    def decode(self, data: bytes) -> Tuple[bytes, bool]:
        try:
            text = data.decode("ascii").strip()
            return binascii.unhexlify(text), True
        except Exception:
            return data, False

    @property
    def name(self) -> str:
        return "Hex"


# Relative frequencies (percent) of letters in English text. Used to decide
# whether a ROT13 rotation actually yields more English-like output than its
# input, so the self-inverse cipher is not applied to already-readable text.
_ENGLISH_LETTER_FREQ = {
    "a": 8.2, "b": 1.5, "c": 2.8, "d": 4.3, "e": 12.7, "f": 2.2, "g": 2.0,
    "h": 6.1, "i": 7.0, "j": 0.15, "k": 0.77, "l": 4.0, "m": 2.4, "n": 6.7,
    "o": 7.5, "p": 1.9, "q": 0.095, "r": 6.0, "s": 6.3, "t": 9.1, "u": 2.8,
    "v": 0.98, "w": 2.4, "x": 0.15, "y": 2.0, "z": 0.074,
}


def _english_likeness(text: str) -> float:
    """Average English letter frequency over the alphabetic characters in text.

    Higher means more English-like. ROT13 ciphertext of English scores low;
    actual English prose scores high. Returns 0.0 when there are no letters.
    """
    letters = [c.lower() for c in text if c.isalpha()]
    if not letters:
        return 0.0
    return sum(_ENGLISH_LETTER_FREQ.get(c, 0.0) for c in letters) / len(letters)


class Rot13Decoder(Decoder):
    """ROT13 decoder."""

    def can_decode(self, data: bytes) -> bool:
        """Only try ROT13 if data looks like it might be text."""
        if len(data) < 8:
            return False

        # If it already looks like base64, prefer Base64/RecursiveBase64.
        # ROT13 on base64-like payloads is almost always a false-positive.
        if looks_like_base64(data):
            return False

        # Try to decode as ASCII
        try:
            text = data.decode("ascii")
        except UnicodeDecodeError:
            return False

        # Check if it looks like it could be English or common text
        # Count letters (a-z, A-Z)
        letter_count = sum(1 for c in text if c.isalpha())
        if letter_count < len(text) * 0.3:  # At least 30% should be letters
            return False

        # Check that most characters are printable
        printable_count = sum(1 for c in text if c.isprintable() or c.isspace())
        if printable_count < len(text) * 0.9:
            return False

        return True

    def decode(self, data: bytes) -> Tuple[bytes, bool]:
        try:
            text = data.decode("ascii")
            decoded = ""
            for char in text:
                if "a" <= char <= "z":
                    decoded += chr((ord(char) - ord("a") + 13) % 26 + ord("a"))
                elif "A" <= char <= "Z":
                    decoded += chr((ord(char) - ord("A") + 13) % 26 + ord("A"))
                else:
                    decoded += char

            # ROT13 is self-inverse, so it cannot tell plaintext from ciphertext
            # by structure alone. Only treat it as a successful decode when the
            # rotation makes the text more English-like; otherwise we would mangle
            # already-readable content into garbage and pollute downstream IOCs.
            if _english_likeness(decoded) <= _english_likeness(text):
                return data, False

            return decoded.encode("ascii"), True
        except Exception:
            return data, False

    @property
    def name(self) -> str:
        return "ROT13"


class XorDecoder(Decoder):
    """Single-byte XOR decoder with best guess."""

    def can_decode(self, data: bytes) -> bool:
        """Check if data might be XOR encoded."""
        if len(data) < 8:
            return False

        # Check if data has some structure that suggests XOR encoding
        # Look for patterns that are common in XOR-encoded data
        # High entropy but some repeating patterns
        diversity = len(set(data)) / len(data)
        if diversity < 0.5:  # Low diversity suggests not XOR
            return False

        # Check for potential XOR patterns (like English text with high bit set)
        high_bit_count = sum(1 for b in data if b & 0x80)
        high_bit_ratio = high_bit_count / len(data)
        if high_bit_ratio < 0.1:  # Not enough high bits
            return False

        return True

    def decode(self, data: bytes) -> Tuple[bytes, bool]:
        from ..utils.helpers import looks_like_text

        best_score = 0
        best_out = data

        for key in range(256):
            decoded = bytes(b ^ key for b in data)
            score = sum(1 for b in decoded if 32 <= b <= 126)  # Printable ASCII
            if score > best_score:
                best_score = score
                best_out = decoded

        # Only return if it looks like text and score is good
        if looks_like_text(best_out) and best_score > len(best_out) * 0.6:
            return best_out, True
        return data, False

    @property
    def name(self) -> str:
        return "XOR"


class PDFDecoder(Decoder):
    """PDF file stream decoder - extracts compressed streams and objects."""

    def __init__(self, max_output_size: int = DEFAULT_MAX_DECOMPRESSED_SIZE):
        self.max_output_size = max_output_size

    def can_decode(self, data: bytes) -> bool:
        """Check if data looks like a PDF file."""
        result = data.startswith(b"%PDF-") and b"%%EOF" in data
        return result

    def decode(self, data: bytes) -> Tuple[bytes, bool]:
        """Extract and decompress PDF streams and objects."""
        try:
            extracted_content = []
            total = 0  # Cap total extracted bytes (FlateDecode streams can be bombs).

            # Find all stream objects with their preceding dictionaries
            # Pattern matches: <<...>> stream ... endstream
            stream_pattern = b"<<([^>]*)>>\\s*stream\\r?\\n(.*?)\\r?\\nendstream"

            matches = re.findall(stream_pattern, data, re.DOTALL)

            for dict_part, stream_data in matches:
                if total >= self.max_output_size:
                    break
                # Check if this stream uses FlateDecode compression
                if b"/FlateDecode" in dict_part:
                    try:
                        # Bound the inflate output so a crafted stream cannot
                        # expand without limit (decompression bomb).
                        decompressed = _bounded_decompress(
                            zlib.decompressobj,
                            stream_data,
                            self.max_output_size - total,
                        )
                        extracted_content.append(decompressed)
                        total += len(decompressed)
                    except Exception:
                        # Decompression failed or exceeded the cap: keep the raw
                        # (compressed, hence small) stream instead.
                        extracted_content.append(stream_data)
                        total += len(stream_data)
                else:
                    extracted_content.append(stream_data)
                    total += len(stream_data)

            # Also extract JavaScript if present
            js_pattern = b"/JavaScript\\s*(.*?)\\s*endobj"
            js_matches = re.findall(js_pattern, data, re.DOTALL | re.IGNORECASE)
            for js in js_matches:
                extracted_content.append(js.strip())

            # Extract embedded files
            embedded_pattern = b"/EmbeddedFile\\s*(.*?)\\s*endobj"
            embedded_matches = re.findall(
                embedded_pattern, data, re.DOTALL | re.IGNORECASE
            )
            for embedded in embedded_matches:
                extracted_content.append(embedded.strip())

            if extracted_content:
                # Return concatenated extracted content
                return b"\n".join(extracted_content), True

            return data, False

        except Exception:
            return data, False

    @property
    def name(self) -> str:
        return "PDF"


class OLEDecoder(Decoder):
    """OLE (Object Linking and Embedding) file decoder - extracts embedded content."""

    # Per-signature match cap: each signature occurrence extracts a window and,
    # for VBA, scans for end markers. Without a cap, a crafted OLE file full of
    # repeated signatures yields gigabytes of output (memory bomb) and the VBA
    # end-marker scan becomes O(n^2). Real OLE files have very few matches.
    MAX_MATCHES_PER_SIGNATURE = 64

    def __init__(self, max_output_size: int = DEFAULT_MAX_DECOMPRESSED_SIZE):
        self.max_output_size = max_output_size

    def can_decode(self, data: bytes) -> bool:
        """Check if data looks like an OLE file."""
        if len(data) < 8:
            return False
        # OLE signature: D0 CF 11 E0 A1 B1 1A E1
        return data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"

    def decode(self, data: bytes) -> Tuple[bytes, bool]:
        """Extract embedded content from OLE files (bounded)."""
        try:
            extracted_content = []
            total = 0
            generators = (
                self._extract_ole_objects(data),
                self._extract_vba_macros(data),
                self._extract_embedded_files(data),
            )
            for gen in generators:
                if total >= self.max_output_size:
                    break
                for chunk in gen:
                    room = self.max_output_size - total
                    if room <= 0:
                        break
                    if len(chunk) > room:
                        chunk = chunk[:room]
                    extracted_content.append(chunk)
                    total += len(chunk)

            if extracted_content:
                return b"\n".join(extracted_content), True

            return data, False

        except Exception:
            return data, False

    def _extract_ole_objects(self, data: bytes):
        """Yield windows around OLE object signatures."""
        ole_signatures = [
            b"\x01\x00\x00\x00",  # OLE object
            b"Package",  # Embedded package
        ]
        for sig in ole_signatures:
            pos = 0
            count = 0
            while count < self.MAX_MATCHES_PER_SIGNATURE:
                pos = data.find(sig, pos)
                if pos == -1:
                    break
                start = max(0, pos - 100)
                end = min(len(data), pos + 1000)
                yield data[start:end]
                pos += len(sig)
                count += 1

    def _extract_vba_macros(self, data: bytes):
        """Yield VBA macro content around project signatures."""
        vba_indicators = [b"VBA", b"PROJECT", b"Attribute VB_Name"]
        end_markers = [b"\x00\x00", b"End Sub", b"End Function"]
        for indicator in vba_indicators:
            pos = 0
            count = 0
            while count < self.MAX_MATCHES_PER_SIGNATURE:
                pos = data.find(indicator, pos)
                if pos == -1:
                    break
                end = len(data)
                for marker in end_markers:
                    marker_pos = data.find(marker, pos)
                    if marker_pos != -1 and marker_pos < end:
                        end = marker_pos + len(marker)
                macro_content = data[pos:end]
                if len(macro_content) > 10:  # Only if substantial content
                    yield macro_content
                pos += len(indicator)
                count += 1

    def _extract_embedded_files(self, data: bytes):
        """Yield windows around embedded file headers."""
        file_headers = [
            b"%PDF-",  # PDF
            b"PK\x03\x04",  # ZIP
            b"MZ",  # PE
            b"\x7fELF",  # ELF
            b"BZ",  # BZIP2
            b"\x1f\x8b",  # GZIP
        ]
        for header in file_headers:
            pos = 0
            count = 0
            while count < self.MAX_MATCHES_PER_SIGNATURE:
                pos = data.find(header, pos)
                if pos == -1:
                    break
                end = min(len(data), pos + 10000)  # 10KB should be enough for headers
                yield data[pos:end]
                pos += len(header)
                count += 1

    @property
    def name(self) -> str:
        return "OLE"


class UUDecoder(Decoder):
    """UUencode decoder - OFF BY DEFAULT (enables smart detection)."""

    def __init__(self, enabled: bool = False):
        self.enabled = enabled

    def can_decode(self, data: bytes) -> bool:
        if not self.enabled:
            return False

        try:
            text = data.decode("ascii")
            # UUencoded data starts with "begin" followed by permissions and filename
            return bool(re.match(r"^begin\s+\d{3}\s+\w+", text, re.MULTILINE))
        except Exception:
            return False

    def decode(self, data: bytes) -> Tuple[bytes, bool]:
        # Implemented with binascii.a2b_uu rather than the stdlib `uu` module,
        # which is deprecated (3.11) and removed in Python 3.13.
        try:
            out = bytearray()
            started = False
            for raw in data.split(b"\n"):
                line = raw.rstrip(b"\r")
                if not started:
                    if line.startswith(b"begin "):
                        started = True
                    continue
                if line.startswith(b"end"):
                    break
                if not line or line == b"`":
                    # ` is the zero-length data line that precedes `end`.
                    continue
                try:
                    out += binascii.a2b_uu(line)
                except binascii.Error:
                    # Some encoders strip trailing whitespace; recompute the
                    # expected byte count from the length char and retry.
                    nbytes = (((line[0] - 32) & 0x3F) * 4 + 5) // 3
                    out += binascii.a2b_uu(line[: nbytes + 1])

            decoded = bytes(out)
            if decoded:
                return decoded, True
            return data, False
        except Exception:
            return data, False

    @property
    def name(self) -> str:
        return "UUEncode"


class ASN1Decoder(Decoder):
    """ASN.1 DER/BER decoder - OFF BY DEFAULT (enables smart detection)."""

    def __init__(self, enabled: bool = False):
        self.enabled = enabled

    def can_decode(self, data: bytes) -> bool:
        if not self.enabled:
            return False

        # ASN.1 typically starts with tag 0x30 (SEQUENCE)
        if len(data) < 4:
            return False

        # Check for common ASN.1 DER/BER signatures
        if data[0] in (
            0x30,
            0x31,
            0x02,
            0x06,
        ):  # SEQUENCE, SET, INTEGER, OBJECT IDENTIFIER
            # Verify length encoding
            if data[1] & 0x80:
                # Long form length
                return data[1] & 0x7F <= 4  # Reasonable length encoding
            return True

        return False

    def decode(self, data: bytes) -> Tuple[bytes, bool]:
        try:
            # Basic ASN.1 parsing - extract readable content
            decoded_content = self._parse_asn1(data)
            if decoded_content:
                return decoded_content, True
            return data, False
        except Exception:
            return data, False

    def _parse_asn1(self, data: bytes, depth: int = 0) -> bytes:
        """Recursively parse ASN.1 structure."""
        if depth > 10 or len(data) < 2:
            return b""

        result = []
        offset = 0

        while offset < len(data):
            # Parse tag
            tag = data[offset]
            offset += 1

            if offset >= len(data):
                break

            # Parse length
            length = data[offset]
            offset += 1

            if length & 0x80:
                # Long form
                len_bytes = length & 0x7F
                if offset + len_bytes > len(data):
                    break
                length = int.from_bytes(data[offset : offset + len_bytes], "big")
                offset += len_bytes

            # Extract value
            if offset + length > len(data):
                break

            value = data[offset : offset + length]
            offset += length

            # Try to extract printable content
            try:
                if tag == 0x04:  # OCTET STRING
                    result.append(value)
                elif tag == 0x0C:  # UTF8String
                    result.append(value)
                elif tag == 0x13:  # PrintableString
                    result.append(value)
            except Exception:
                pass

        return b"\n".join(result)

    @property
    def name(self) -> str:
        return "ASN.1"


class QuotedPrintableDecoder(Decoder):
    """Quoted-Printable decoder - OFF BY DEFAULT (enables smart detection)."""

    def __init__(self, enabled: bool = False):
        self.enabled = enabled

    def can_decode(self, data: bytes) -> bool:
        if not self.enabled:
            return False

        try:
            text = data.decode("ascii")
            # Look for typical quoted-printable patterns
            return "=" in text and re.search(r"=[0-9A-F]{2}", text, re.IGNORECASE)
        except Exception:
            return False

    def decode(self, data: bytes) -> Tuple[bytes, bool]:
        try:
            import quopri

            decoded = quopri.decodestring(data)
            if decoded != data:
                return decoded, True
            return data, False
        except Exception:
            return data, False

    @property
    def name(self) -> str:
        return "QuotedPrintable"


class Base32Decoder(Decoder):
    """Base32 decoder - OFF BY DEFAULT (enables smart detection)."""

    def __init__(self, enabled: bool = False):
        self.enabled = enabled

    def can_decode(self, data: bytes) -> bool:
        if not self.enabled:
            return False

        try:
            text = data.decode("ascii").strip()
            # Base32 uses A-Z and 2-7, typically multiple of 8
            if not re.match(r"^[A-Z2-7=]+$", text):
                return False
            if len(text) % 8 != 0 and len(text) % 8 != 7:  # Allow for missing padding
                return False
            return len(text) >= 16  # Need reasonable length
        except Exception:
            return False

    def decode(self, data: bytes) -> Tuple[bytes, bool]:
        try:
            import base64

            text = data.decode("ascii").strip()
            # Add padding if needed
            padding = (8 - len(text) % 8) % 8
            text += "=" * padding
            decoded = base64.b32decode(text)
            return decoded, True
        except Exception:
            return data, False

    @property
    def name(self) -> str:
        return "Base32"


class URLDecoder(Decoder):
    """URL percent-encoding decoder."""

    def can_decode(self, data: bytes) -> bool:
        try:
            text = data.decode("utf-8", errors="ignore")
            return bool(re.search(r"%[0-9A-Fa-f]{2}", text))
        except Exception:
            return False

    def decode(self, data: bytes) -> Tuple[bytes, bool]:
        try:
            text = data.decode("utf-8", errors="ignore")
            # Use a bytearray: byte concatenation in a loop (result += ...) is
            # O(n^2) and hangs on percent-heavy payloads.
            result = bytearray()
            n = len(text)
            i = 0
            while i < n:
                ch = text[i]
                if ch == "%" and i + 2 < n:
                    try:
                        result.append(int(text[i + 1 : i + 3], 16))
                        i += 3
                        continue
                    except ValueError:
                        pass
                if ch == "+":
                    result += b" "
                else:
                    result += ch.encode("utf-8")
                i += 1
            out = bytes(result)
            return (out if out else data), bool(out and out != data)
        except Exception:
            return data, False

    @property
    def name(self) -> str:
        return "URLDecoder"


class HTMLEntityDecoder(Decoder):
    """HTML entity decoder."""

    def can_decode(self, data: bytes) -> bool:
        try:
            text = data.decode("utf-8", errors="ignore")
            return bool(
                re.search(r"&#(?:\d+|x[0-9A-Fa-f]+);|&[a-z]+;", text, re.IGNORECASE)
            )
        except Exception:
            return False

    _ENTITY_RE = re.compile(r"&#(\d+);|&#x([0-9A-Fa-f]+);|&([a-zA-Z]+);")
    _NAMED = {
        "nbsp": 0x20,
        "lt": ord("<"),
        "gt": ord(">"),
        "amp": ord("&"),
        "quot": ord('"'),
        "apos": ord("'"),
    }

    def decode(self, data: bytes) -> Tuple[bytes, bool]:
        try:
            text = data.decode("utf-8", errors="ignore")

            # Single-pass substitution: the previous char-by-char scan sliced
            # text[i:] and re-ran the regex for every character (O(n^2)), which
            # hangs on entity-heavy payloads.
            def _sub(m: "re.Match") -> str:
                dec, hexv, name = m.group(1), m.group(2), m.group(3)
                if dec is not None:
                    try:
                        return chr(int(dec))
                    except (ValueError, OverflowError):
                        return m.group(0)
                if hexv is not None:
                    try:
                        return chr(int(hexv, 16))
                    except (ValueError, OverflowError):
                        return m.group(0)
                code = self._NAMED.get(name.lower())
                return chr(code) if code is not None else m.group(0)

            decoded = self._ENTITY_RE.sub(_sub, text).encode("utf-8")
            return decoded, decoded != data
        except Exception:
            return data, False

    @property
    def name(self) -> str:
        return "HTMLEntity"


class UnicodeEscapeDecoder(Decoder):
    """Unicode escape sequences decoder."""

    def can_decode(self, data: bytes) -> bool:
        try:
            text = data.decode("utf-8", errors="ignore")
            return bool(re.search(r"\\u[0-9A-Fa-f]{4}|\\U[0-9A-Fa-f]{8}", text))
        except Exception:
            return False

    def decode(self, data: bytes) -> Tuple[bytes, bool]:
        try:
            text = data.decode("utf-8", errors="ignore")
            result = []
            i = 0

            while i < len(text):
                # Try \\UXXXXXXXX
                if text[i : i + 2] == "\\U" and i + 10 <= len(text):
                    try:
                        code = int(text[i + 2 : i + 10], 16)
                        result.append(chr(code))
                        i += 10
                        continue
                    except (ValueError, OverflowError):
                        pass

                # Try \\uXXXX
                if text[i : i + 2] == "\\u" and i + 6 <= len(text):
                    try:
                        code = int(text[i + 2 : i + 6], 16)
                        result.append(chr(code))
                        i += 6
                        continue
                    except (ValueError, OverflowError):
                        pass

                result.append(text[i])
                i += 1

            decoded = "".join(result).encode("utf-8")
            return decoded, decoded != data
        except Exception:
            return data, False

    @property
    def name(self) -> str:
        return "UnicodeEscape"
