"""Object-graph-aware PDF parser.

The old PDF decoder found ``stream ... endstream`` byte ranges with a regex and
guessed at filters from a text window. That cannot resolve indirect references
(``/JS 5 0 R``), cannot see objects packed inside an object stream
(``/Type /ObjStm``), and mislabels filter chains.

This module parses the PDF as an object graph:

* every top-level ``N G obj ... endobj`` is parsed into a Python value (dict,
  array, name, number, string, reference, or a stream object);
* object streams (``/Type /ObjStm``) are decompressed and their packed objects
  added to the object table, so objects that the regex approach cannot see at
  all become visible;
* indirect references are resolved through the object table;
* stream ``/Filter`` chains are applied (FlateDecode, ASCIIHexDecode,
  ASCII85Decode, LZWDecode), including PNG/TIFF predictors used by xref
  streams.

Everything is bounded: decode output is capped, reference resolution is
depth-limited and cycle-guarded, and the number of parsed objects is limited so
a crafted PDF cannot exhaust memory or loop.
"""

from __future__ import annotations

import re
import struct
import zlib
from typing import Any, Dict, List, Optional, Tuple

MAX_OBJECTS = 50000
MAX_RESOLVE_DEPTH = 32


class PDFName:
    """A PDF name object (e.g. ``/FlateDecode``)."""

    __slots__ = ("value",)

    def __init__(self, value: str):
        self.value = value

    def __repr__(self) -> str:
        return f"/{self.value}"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, PDFName) and other.value == self.value

    def __hash__(self) -> int:
        return hash(("PDFName", self.value))


class PDFRef:
    """An indirect reference (``N G R``)."""

    __slots__ = ("num", "gen")

    def __init__(self, num: int, gen: int):
        self.num = num
        self.gen = gen

    def __repr__(self) -> str:
        return f"{self.num} {self.gen} R"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, PDFRef) and other.num == self.num and other.gen == self.gen

    def __hash__(self) -> int:
        return hash(("PDFRef", self.num, self.gen))


class PDFStream:
    """A stream object: its dictionary plus the raw (still-encoded) bytes."""

    __slots__ = ("dict", "raw")

    def __init__(self, d: Dict[Any, Any], raw: bytes):
        self.dict = d
        self.raw = raw


_WHITESPACE = b"\x00\t\n\x0c\r "
_DELIM = b"()<>[]{}/%"


class _Lexer:
    """Tokenize a slice of PDF content into primitive objects."""

    def __init__(self, data: bytes, pos: int = 0):
        self.data = data
        self.pos = pos
        self.n = len(data)

    def _skip_ws(self) -> None:
        d, n = self.data, self.n
        while self.pos < n:
            c = d[self.pos]
            if c in _WHITESPACE:
                self.pos += 1
            elif c == 0x25:  # % comment to end of line
                while self.pos < n and d[self.pos] not in (0x0A, 0x0D):
                    self.pos += 1
            else:
                break

    def parse_object(self, depth: int = 0) -> Any:
        if depth > 200:
            return None
        self._skip_ws()
        if self.pos >= self.n:
            return None
        c = self.data[self.pos]

        if c == 0x2F:  # /
            return self._parse_name()
        if c == 0x28:  # (
            return self._parse_literal_string()
        if c == 0x3C:  # <
            if self.pos + 1 < self.n and self.data[self.pos + 1] == 0x3C:
                return self._parse_dict(depth)
            return self._parse_hex_string()
        if c == 0x5B:  # [
            return self._parse_array(depth)
        # number, reference, keyword
        return self._parse_token()

    def _parse_name(self) -> PDFName:
        self.pos += 1  # skip /
        d, n = self.data, self.n
        out = bytearray()
        while self.pos < n:
            c = d[self.pos]
            if c in _WHITESPACE or c in _DELIM:
                break
            if c == 0x23 and self.pos + 2 < n:  # #XX hex escape
                try:
                    out.append(int(d[self.pos + 1 : self.pos + 3], 16))
                    self.pos += 3
                    continue
                except ValueError:
                    pass
            out.append(c)
            self.pos += 1
        return PDFName(out.decode("latin-1"))

    def _parse_literal_string(self) -> bytes:
        self.pos += 1  # skip (
        d, n = self.data, self.n
        depth = 1
        out = bytearray()
        while self.pos < n and depth > 0:
            c = d[self.pos]
            if c == 0x5C:  # backslash escape
                self.pos += 1
                if self.pos >= n:
                    break
                e = d[self.pos]
                mapping = {0x6E: 0x0A, 0x72: 0x0D, 0x74: 0x09, 0x62: 0x08, 0x66: 0x0C}
                if e in mapping:
                    out.append(mapping[e])
                    self.pos += 1
                elif 0x30 <= e <= 0x37:  # octal escape (1-3 digits)
                    oct_digits = bytearray()
                    while self.pos < n and len(oct_digits) < 3 and 0x30 <= d[self.pos] <= 0x37:
                        oct_digits.append(d[self.pos])
                        self.pos += 1
                    out.append(int(oct_digits, 8) & 0xFF)
                else:
                    out.append(e)
                    self.pos += 1
            elif c == 0x28:
                depth += 1
                out.append(c)
                self.pos += 1
            elif c == 0x29:
                depth -= 1
                if depth > 0:
                    out.append(c)
                self.pos += 1
            else:
                out.append(c)
                self.pos += 1
        return bytes(out)

    def _parse_hex_string(self) -> bytes:
        self.pos += 1  # skip <
        d, n = self.data, self.n
        hexd = bytearray()
        while self.pos < n and d[self.pos] != 0x3E:
            c = d[self.pos]
            if c not in _WHITESPACE:
                hexd.append(c)
            self.pos += 1
        self.pos += 1  # skip >
        if len(hexd) % 2:
            hexd.append(0x30)
        try:
            return bytes.fromhex(hexd.decode("latin-1"))
        except ValueError:
            return b""

    def _parse_array(self, depth: int) -> List[Any]:
        self.pos += 1  # skip [
        out: List[Any] = []
        while True:
            self._skip_ws()
            if self.pos >= self.n or self.data[self.pos] == 0x5D:  # ]
                self.pos += 1
                break
            if len(out) > 100000:
                break
            obj = self.parse_object(depth + 1)
            if obj is None and (self.pos >= self.n):
                break
            out.append(obj)
        return out

    def _parse_dict(self, depth: int) -> Any:
        self.pos += 2  # skip <<
        d: Dict[Any, Any] = {}
        while True:
            self._skip_ws()
            if self.pos + 1 < self.n and self.data[self.pos : self.pos + 2] == b">>":
                self.pos += 2
                break
            if self.pos >= self.n:
                break
            key = self.parse_object(depth + 1)
            if not isinstance(key, PDFName):
                # Malformed; bail out of the dict.
                break
            value = self.parse_object(depth + 1)
            d[key.value] = value
            if len(d) > 100000:
                break
        return d

    def _parse_token(self) -> Any:
        d, n = self.data, self.n
        start = self.pos
        while self.pos < n and d[self.pos] not in _WHITESPACE and d[self.pos] not in _DELIM:
            self.pos += 1
        tok = d[start : self.pos]
        if not tok:
            self.pos += 1
            return None
        if tok == b"true":
            return True
        if tok == b"false":
            return False
        if tok == b"null":
            return None
        # Could be an integer that starts a reference "N G R".
        if re.fullmatch(rb"[+-]?\d+", tok):
            num = int(tok)
            save = self.pos
            self._skip_ws()
            gstart = self.pos
            while self.pos < n and d[self.pos] not in _WHITESPACE and d[self.pos] not in _DELIM:
                self.pos += 1
            gtok = d[gstart : self.pos]
            if re.fullmatch(rb"\d+", gtok):
                self._skip_ws()
                if self.pos < n and d[self.pos] in (0x52, 0x6F):  # R or obj
                    kw = d[self.pos]
                    if kw == 0x52:  # R -> reference
                        self.pos += 1
                        return PDFRef(num, int(gtok))
            self.pos = save
            return num
        if re.fullmatch(rb"[+-]?\d*\.\d+", tok):
            try:
                return float(tok)
            except ValueError:
                return 0.0
        # Unknown keyword.
        return _Keyword(tok.decode("latin-1"))


class _Keyword:
    __slots__ = ("value",)

    def __init__(self, value: str):
        self.value = value


# ---------------------------------------------------------------------------
# Filters
# ---------------------------------------------------------------------------


def _ascii_hex_decode(data: bytes) -> bytes:
    end = data.find(b">")
    if end != -1:
        data = data[:end]
    hexd = bytes(c for c in data if c not in _WHITESPACE)
    if len(hexd) % 2:
        hexd += b"0"
    try:
        return bytes.fromhex(hexd.decode("latin-1"))
    except ValueError:
        return b""


def _ascii85_decode(data: bytes) -> bytes:
    # Strip optional <~ prefix and ~> suffix.
    if data[:2] == b"<~":
        data = data[2:]
    end = data.find(b"~>")
    if end != -1:
        data = data[:end]
    out = bytearray()
    group: List[int] = []
    for c in data:
        if c in _WHITESPACE:
            continue
        if c == 0x7A and not group:  # 'z' -> four zero bytes
            out += b"\x00\x00\x00\x00"
            continue
        if 0x21 <= c <= 0x75:
            group.append(c - 0x21)
            if len(group) == 5:
                val = 0
                for g in group:
                    val = val * 85 + g
                out += struct.pack(">I", val & 0xFFFFFFFF)
                group = []
    if group:
        count = len(group)
        group += [84] * (5 - count)
        val = 0
        for g in group:
            val = val * 85 + g
        out += struct.pack(">I", val & 0xFFFFFFFF)[: count - 1]
    return bytes(out)


def _lzw_decode(data: bytes, early_change: int = 1) -> bytes:
    """Decode PDF LZWDecode (variable-width codes, 9-12 bits)."""
    out = bytearray()
    bit_buffer = 0
    bit_count = 0
    code_width = 9
    dict_size = 258
    table: Dict[int, bytes] = {i: bytes([i]) for i in range(256)}
    prev: Optional[bytes] = None
    CLEAR = 256
    EOD = 257

    for byte in data:
        bit_buffer = (bit_buffer << 8) | byte
        bit_count += 8
        while bit_count >= code_width:
            bit_count -= code_width
            code = (bit_buffer >> bit_count) & ((1 << code_width) - 1)
            if code == EOD:
                return bytes(out)
            if code == CLEAR:
                code_width = 9
                dict_size = 258
                table = {i: bytes([i]) for i in range(256)}
                prev = None
                continue
            if code in table:
                entry = table[code]
            elif code == dict_size and prev is not None:
                entry = prev + prev[:1]
            else:
                return bytes(out)  # corrupt
            out += entry
            if prev is not None:
                table[dict_size] = prev + entry[:1]
                dict_size += 1
                if dict_size + early_change - 1 >= (1 << code_width) and code_width < 12:
                    code_width += 1
            prev = entry
            if len(out) > 200 * 1024 * 1024:
                break
    return bytes(out)


def _apply_predictor(data: bytes, predictor: int, colors: int, bpc: int, columns: int) -> bytes:
    if predictor < 2:
        return data
    bytes_per_pixel = max(1, (colors * bpc + 7) // 8)
    row_len = (colors * bpc * columns + 7) // 8
    if row_len <= 0:
        return data
    if predictor == 2:  # TIFF predictor 2
        out = bytearray(data)
        for r in range(0, len(out), row_len):
            row = out[r : r + row_len]
            for i in range(bytes_per_pixel, len(row)):
                row[i] = (row[i] + row[i - bytes_per_pixel]) & 0xFF
            out[r : r + row_len] = row
        return bytes(out)
    # PNG predictors: each row prefixed with a filter-type byte.
    out = bytearray()
    prev = bytearray(row_len)
    stride = row_len + 1
    for r in range(0, len(data), stride):
        chunk = data[r : r + stride]
        if len(chunk) < 1:
            break
        ftype = chunk[0]
        row = bytearray(chunk[1 : 1 + row_len])
        if len(row) < row_len:
            row += bytes(row_len - len(row))
        for i in range(row_len):
            a = row[i - bytes_per_pixel] if i >= bytes_per_pixel else 0
            b = prev[i]
            c = prev[i - bytes_per_pixel] if i >= bytes_per_pixel else 0
            x = row[i]
            if ftype == 0:
                val = x
            elif ftype == 1:
                val = x + a
            elif ftype == 2:
                val = x + b
            elif ftype == 3:
                val = x + ((a + b) >> 1)
            elif ftype == 4:
                p = a + b - c
                pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                pr = a if (pa <= pb and pa <= pc) else (b if pb <= pc else c)
                val = x + pr
            else:
                val = x
            row[i] = val & 0xFF
        out += row
        prev = row
    return bytes(out)


class PDFDocument:
    """Parse a PDF into an object table and resolve/decode on demand."""

    _OBJ_RE = re.compile(rb"(\d+)\s+(\d+)\s+obj\b")

    def __init__(self, data: bytes, max_output: int = 100 * 1024 * 1024):
        self.data = data
        self.max_output = max_output
        self.objects: Dict[Tuple[int, int], Any] = {}
        self._num_index: Dict[int, Tuple[int, int]] = {}
        self._parse_all_objects()
        self._expand_object_streams()

    # -- parsing --------------------------------------------------------------

    def _parse_all_objects(self) -> None:
        data = self.data
        for m in self._OBJ_RE.finditer(data):
            if len(self.objects) >= MAX_OBJECTS:
                break
            num, gen = int(m.group(1)), int(m.group(2))
            body_start = m.end()
            obj = self._parse_indirect_body(body_start)
            if obj is not None or (num, gen) not in self.objects:
                self.objects[(num, gen)] = obj
                self._num_index[num] = (num, gen)

    def _parse_indirect_body(self, start: int) -> Any:
        lexer = _Lexer(self.data, start)
        value = lexer.parse_object()
        lexer._skip_ws()
        # A stream follows a dictionary when the `stream` keyword appears.
        if isinstance(value, dict) and self.data[lexer.pos : lexer.pos + 6] == b"stream":
            p = lexer.pos + 6
            # Skip the CRLF/LF after `stream`.
            if self.data[p : p + 2] == b"\r\n":
                p += 2
            elif self.data[p : p + 1] in (b"\n", b"\r"):
                p += 1
            length = value.get("Length")
            raw = None
            if isinstance(length, int) and 0 <= length <= len(self.data):
                candidate_end = p + length
                # Validate against the endstream marker; fall back to search.
                tail = self.data[candidate_end : candidate_end + 20]
                if b"endstream" in tail:
                    raw = self.data[p:candidate_end]
            if raw is None:
                end = self.data.find(b"endstream", p)
                if end == -1:
                    end = len(self.data)
                raw = self.data[p:end]
                if raw.endswith(b"\r\n"):
                    raw = raw[:-2]
                elif raw.endswith(b"\n") or raw.endswith(b"\r"):
                    raw = raw[:-1]
            return PDFStream(value, raw)
        return value

    def _expand_object_streams(self) -> None:
        """Decompress ``/Type /ObjStm`` streams and add their packed objects.

        These objects are invisible to a byte-window/regex approach because they
        do not appear as ``N G obj`` anywhere in the file — they live compressed
        inside another object's stream.
        """
        for key in list(self.objects.keys()):
            if len(self.objects) >= MAX_OBJECTS:
                break
            obj = self.objects.get(key)
            if not isinstance(obj, PDFStream):
                continue
            t = obj.dict.get("Type")
            if not (isinstance(t, PDFName) and t.value == "ObjStm"):
                continue
            try:
                decoded = self.decode_stream(obj)
            except Exception:
                continue
            n = obj.dict.get("N")
            first = obj.dict.get("First")
            n = self.resolve(n)
            first = self.resolve(first)
            if not isinstance(n, int) or not isinstance(first, int):
                continue
            header = decoded[:first]
            nums = re.findall(rb"\d+", header)
            # Header is pairs of (object number, offset).
            for i in range(0, min(len(nums), 2 * n), 2):
                try:
                    onum = int(nums[i])
                    ooff = int(nums[i + 1])
                except (ValueError, IndexError):
                    break
                obj_start = first + ooff
                if obj_start >= len(decoded):
                    continue
                sub = _Lexer(decoded, obj_start).parse_object()
                if (onum, 0) not in self.objects:
                    self.objects[(onum, 0)] = sub
                    self._num_index.setdefault(onum, (onum, 0))

    # -- resolution -----------------------------------------------------------

    def resolve(self, obj: Any, depth: int = 0) -> Any:
        if depth > MAX_RESOLVE_DEPTH:
            return None
        if isinstance(obj, PDFRef):
            key = (obj.num, obj.gen)
            target = self.objects.get(key)
            if target is None:
                target = self.objects.get(self._num_index.get(obj.num, (obj.num, 0)))
            if target is None:
                return None
            return self.resolve(target, depth + 1)
        return obj

    # -- stream decoding ------------------------------------------------------

    def _filter_list(self, d: Dict[Any, Any]) -> List[str]:
        filt = self.resolve(d.get("Filter"))
        names: List[str] = []
        if isinstance(filt, PDFName):
            names = [filt.value]
        elif isinstance(filt, list):
            for f in filt:
                f = self.resolve(f)
                if isinstance(f, PDFName):
                    names.append(f.value)
        return names

    def _decode_parms_list(self, d: Dict[Any, Any], count: int) -> List[Any]:
        parms = self.resolve(d.get("DecodeParms") or d.get("DP"))
        if isinstance(parms, list):
            return [self.resolve(p) for p in parms] + [None] * (count - len(parms))
        return [parms] + [None] * (count - 1)

    def decode_stream(self, stream: PDFStream) -> bytes:
        data = stream.raw
        filters = self._filter_list(stream.dict)
        parms = self._decode_parms_list(stream.dict, len(filters))
        for name, parm in zip(filters, parms):
            if len(data) > self.max_output:
                break
            if name in ("FlateDecode", "Fl"):
                try:
                    # Bound the inflate output so a crafted stream cannot expand
                    # without limit (decompression bomb). If the output would
                    # exceed the cap, keep the raw (compressed, hence small)
                    # bytes rather than emitting a truncated blob.
                    d = zlib.decompressobj()
                    inflated = d.decompress(data, self.max_output + 1)
                    if len(inflated) > self.max_output:
                        return stream.raw
                    data = inflated
                except Exception:
                    break
            elif name in ("ASCIIHexDecode", "AHx"):
                data = _ascii_hex_decode(data)
            elif name in ("ASCII85Decode", "A85"):
                data = _ascii85_decode(data)
            elif name in ("LZWDecode", "LZW"):
                ec = 1
                if isinstance(parm, dict):
                    ec = self.resolve(parm.get("EarlyChange", 1)) or 1
                data = _lzw_decode(data, early_change=int(ec))
            else:
                # Unsupported / image filter (DCTDecode, etc.): stop here.
                break

            if isinstance(parm, dict):
                pred = self.resolve(parm.get("Predictor", 1)) or 1
                if isinstance(pred, int) and pred >= 2:
                    colors = int(self.resolve(parm.get("Colors", 1)) or 1)
                    bpc = int(self.resolve(parm.get("BitsPerComponent", 8)) or 8)
                    columns = int(self.resolve(parm.get("Columns", 1)) or 1)
                    data = _apply_predictor(data, pred, colors, bpc, columns)
        return data
