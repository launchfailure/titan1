"""Compound File Binary (CFB / OLE2) structural parser and MS-OVBA VBA
decompression.

This replaces the old signature-window carving in :class:`OLEDecoder` with a
real walk of the CFB structure defined by [MS-CFB]: the header, the FAT/DIFAT
sector-allocation tables, the directory tree, and the mini-stream / mini-FAT
used for small streams. Streams are enumerated by their real directory-path
names (e.g. ``Macros/VBA/Module1``) so extracted artifacts are labeled after
the structure they came from rather than an offset window.

VBA source is stored inside module streams as an [MS-OVBA] *CompressedContainer*
(a run-length + copy-token scheme). ``decompress_ovba`` implements that
container format so a crafted document with a macro yields the actual
decompressed VBA source instead of a byte window around the ``Attribute``
string.

Every parser is written defensively with hard bounds: the total emitted bytes
are capped, sector-chain walks are bounded by the sector count (so a cyclic FAT
cannot loop forever), and directory traversal is depth- and visit-bounded. This
keeps the parser safe on hostile input — a design goal the engine enforces
elsewhere too.
"""

from __future__ import annotations

import struct
from typing import List, Optional, Tuple

CFB_SIGNATURE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"

# Special FAT sector values ([MS-CFB] 2.2).
_MAXREGSECT = 0xFFFFFFFA
_DIFSECT = 0xFFFFFFFC
_FATSECT = 0xFFFFFFFD
_ENDOFCHAIN = 0xFFFFFFFE
_FREESECT = 0xFFFFFFFF
_NOSTREAM = 0xFFFFFFFF

# Directory object types.
_OBJ_STORAGE = 1
_OBJ_STREAM = 2
_OBJ_ROOT = 5


class CFBError(ValueError):
    """Raised when the input is not a well-formed CFB file."""


class DirEntry:
    """One directory entry in the CFB directory stream."""

    __slots__ = (
        "index",
        "name",
        "obj_type",
        "left",
        "right",
        "child",
        "start_sector",
        "size",
    )

    def __init__(
        self,
        index: int,
        name: str,
        obj_type: int,
        left: int,
        right: int,
        child: int,
        start_sector: int,
        size: int,
    ):
        self.index = index
        self.name = name
        self.obj_type = obj_type
        self.left = left
        self.right = right
        self.child = child
        self.start_sector = start_sector
        self.size = size


class CFBReader:
    """Parse a Compound File Binary and expose streams by directory path."""

    def __init__(self, data: bytes, max_total_bytes: int = 100 * 1024 * 1024):
        self.data = data
        self.max_total_bytes = max_total_bytes
        self._parse_header()
        self._read_fat()
        self._read_directory()
        self._read_minifat()

    # -- header ---------------------------------------------------------------

    def _parse_header(self) -> None:
        data = self.data
        if len(data) < 512 or data[:8] != CFB_SIGNATURE:
            raise CFBError("not a CFB file (bad signature)")

        # Sector shift is a power of two: 9 => 512-byte sectors (v3),
        # 12 => 4096-byte sectors (v4).
        (self.minor_version, self.major_version, byte_order) = struct.unpack(
            "<HHH", data[24:30]
        )
        if byte_order != 0xFFFE:
            raise CFBError("unsupported byte order")

        (sector_shift, mini_sector_shift) = struct.unpack("<HH", data[30:34])
        if sector_shift not in (9, 12) or mini_sector_shift != 6:
            raise CFBError("unsupported sector shift")
        self.sector_size = 1 << sector_shift
        self.mini_sector_size = 1 << mini_sector_shift

        (
            self.num_dir_sectors,
            self.num_fat_sectors,
            self.first_dir_sector,
            _transaction_sig,
            self.mini_stream_cutoff,
            self.first_minifat_sector,
            self.num_minifat_sectors,
            self.first_difat_sector,
            self.num_difat_sectors,
        ) = struct.unpack("<IIIIIIIII", data[40:76])

        if self.mini_stream_cutoff == 0:
            self.mini_stream_cutoff = 4096

        # Total number of sectors after the 512-byte header.
        self.total_sectors = max(0, (len(data) - 512) // self.sector_size)

        # First 109 DIFAT entries live in the header.
        self._difat_head = list(struct.unpack("<109I", data[76:512]))

    def _sector_offset(self, sector: int) -> int:
        return 512 + sector * self.sector_size

    def _read_sector(self, sector: int) -> bytes:
        off = self._sector_offset(sector)
        return self.data[off : off + self.sector_size]

    # -- FAT / DIFAT ----------------------------------------------------------

    def _read_fat(self) -> None:
        # Assemble the list of FAT sector locations from the DIFAT: the 109
        # header entries plus any additional DIFAT sectors chained together.
        fat_sectors: List[int] = [s for s in self._difat_head if s <= _MAXREGSECT]

        next_difat = self.first_difat_sector
        seen_difat = set()
        # Each DIFAT sector holds (sector_size/4 - 1) FAT locations plus a
        # pointer to the next DIFAT sector in its last 4 bytes.
        per = self.sector_size // 4
        while (
            next_difat <= _MAXREGSECT
            and next_difat < self.total_sectors
            and next_difat not in seen_difat
            and len(fat_sectors) < self.total_sectors + per
        ):
            seen_difat.add(next_difat)
            sec = self._read_sector(next_difat)
            if len(sec) < self.sector_size:
                break
            entries = struct.unpack(f"<{per}I", sec)
            for s in entries[:-1]:
                if s <= _MAXREGSECT:
                    fat_sectors.append(s)
            next_difat = entries[-1]

        # Build the FAT: one big array of next-sector pointers.
        fat: List[int] = []
        for fs in fat_sectors:
            if fs >= self.total_sectors:
                continue
            sec = self._read_sector(fs)
            if len(sec) < self.sector_size:
                continue
            fat.extend(struct.unpack(f"<{self.sector_size // 4}I", sec))
        self.fat = fat

    def _chain(self, start: int) -> List[int]:
        """Follow a FAT chain from ``start`` to end-of-chain, bounded."""
        chain: List[int] = []
        sector = start
        limit = len(self.fat) + 1
        seen = set()
        while sector <= _MAXREGSECT and len(chain) < limit:
            if sector in seen or sector >= len(self.fat):
                break
            seen.add(sector)
            chain.append(sector)
            sector = self.fat[sector]
        return chain

    def _read_chain(self, start: int, size: Optional[int] = None) -> bytes:
        out = bytearray()
        for sector in self._chain(start):
            out += self._read_sector(sector)
            if len(out) > self.max_total_bytes:
                break
        if size is not None and size <= len(out):
            return bytes(out[:size])
        return bytes(out)

    # -- directory ------------------------------------------------------------

    def _read_directory(self) -> None:
        raw = self._read_chain(self.first_dir_sector)
        entries: List[DirEntry] = []
        for i in range(0, len(raw) // 128):
            off = i * 128
            entry = raw[off : off + 128]
            name_len = struct.unpack("<H", entry[64:66])[0]
            obj_type = entry[66]
            if obj_type not in (_OBJ_STORAGE, _OBJ_STREAM, _OBJ_ROOT):
                # Unused/unknown entry; keep a placeholder so sibling IDs (which
                # index into this list) stay aligned.
                entries.append(
                    DirEntry(i, "", 0, _NOSTREAM, _NOSTREAM, _NOSTREAM, 0, 0)
                )
                continue
            if name_len < 2:
                name = ""
            else:
                name = entry[0 : name_len - 2].decode("utf-16-le", errors="replace")
            left, right, child = struct.unpack("<III", entry[68:80])
            start_sector, size_lo, size_hi = struct.unpack("<III", entry[116:128])
            size = size_lo | (size_hi << 32)
            entries.append(
                DirEntry(i, name, obj_type, left, right, child, start_sector, size)
            )
        self.dir_entries = entries

        if not entries or entries[0].obj_type != _OBJ_ROOT:
            raise CFBError("missing root directory entry")
        self.root = entries[0]

    def _read_minifat(self) -> None:
        # The mini stream is stored in the root entry's regular-sector chain.
        self._mini_stream = self._read_chain(self.root.start_sector, self.root.size)
        raw = self._read_chain(self.first_minifat_sector)
        count = len(raw) // 4
        self.minifat = list(struct.unpack(f"<{count}I", raw[: count * 4])) if count else []

    def _read_mini_chain(self, start: int, size: int) -> bytes:
        out = bytearray()
        sector = start
        seen = set()
        while sector <= _MAXREGSECT and len(out) < size + self.mini_sector_size:
            if sector in seen or sector >= len(self.minifat):
                break
            seen.add(sector)
            off = sector * self.mini_sector_size
            out += self._mini_stream[off : off + self.mini_sector_size]
            sector = self.minifat[sector]
            if len(out) > self.max_total_bytes:
                break
        return bytes(out[:size])

    def read_stream(self, entry: DirEntry) -> bytes:
        """Return the bytes of a stream directory entry."""
        if entry.obj_type != _OBJ_STREAM:
            return b""
        if entry.size < self.mini_stream_cutoff:
            return self._read_mini_chain(entry.start_sector, entry.size)
        return self._read_chain(entry.start_sector, entry.size)

    # -- path enumeration -----------------------------------------------------

    def streams(self) -> List[Tuple[str, DirEntry]]:
        """Enumerate all streams as ``(path, entry)`` in a deterministic order.

        The directory is a red-black tree per storage; we walk it in-order and
        recurse into child storages, building slash-separated paths. Traversal
        is bounded by the number of directory entries so a corrupted tree with
        cyclic sibling pointers cannot loop forever.
        """
        results: List[Tuple[str, DirEntry]] = []
        n = len(self.dir_entries)
        visited: set = set()

        def walk_siblings(node_id: int, prefix: str, depth: int) -> None:
            if depth > 64:
                return
            stack = [node_id]
            while stack:
                nid = stack.pop()
                if nid == _NOSTREAM or nid >= n or nid in visited:
                    continue
                visited.add(nid)
                entry = self.dir_entries[nid]
                if entry.left != _NOSTREAM:
                    stack.append(entry.left)
                if entry.right != _NOSTREAM:
                    stack.append(entry.right)
                path = f"{prefix}/{entry.name}" if prefix else entry.name
                if entry.obj_type == _OBJ_STREAM:
                    results.append((path, entry))
                elif entry.obj_type == _OBJ_STORAGE:
                    if entry.child != _NOSTREAM:
                        walk_siblings(entry.child, path, depth + 1)

        if self.root.child != _NOSTREAM:
            walk_siblings(self.root.child, "", 0)
        results.sort(key=lambda t: t[0])
        return results


# ---------------------------------------------------------------------------
# MS-OVBA VBA source decompression
# ---------------------------------------------------------------------------


def decompress_ovba(compressed: bytes, max_output: int = 16 * 1024 * 1024) -> bytes:
    """Decompress an [MS-OVBA] 2.4.1 CompressedContainer.

    The container starts with a 0x01 signature byte, followed by one or more
    *CompressedChunks*. Each chunk has a 2-byte header giving its size and a
    flag selecting compressed vs. raw storage; compressed chunks are a stream
    of flag bytes, each governing eight following tokens that are either a
    literal byte or a copy (offset,length) back-reference into the output.

    Returns the decompressed bytes, bounded by ``max_output``. Raises no
    exception on malformed input beyond returning what was decoded so far — the
    decoder layer treats a short/failed result as "not a container".
    """
    if not compressed or compressed[0] != 0x01:
        raise CFBError("not an MS-OVBA compressed container")

    out = bytearray()
    i = 1
    n = len(compressed)
    while i < n and len(out) < max_output:
        if i + 2 > n:
            break
        header = struct.unpack("<H", compressed[i : i + 2])[0]
        i += 2
        chunk_size = (header & 0x0FFF) + 3  # CompressedChunkSize
        chunk_flag = (header >> 15) & 0x01
        chunk_sig = (header >> 12) & 0x07
        if chunk_sig != 0b011:
            # Not a valid chunk signature; stop rather than misparse.
            break
        chunk_end = i + (chunk_size - 2)
        if chunk_flag == 0:
            # Raw (uncompressed) chunk: exactly 4096 bytes of data.
            raw = compressed[i : i + 4096]
            out += raw
            i += 4096
            continue

        chunk_data_end = min(chunk_end, n)
        decompressed_chunk_start = len(out)
        while i < chunk_data_end and len(out) < max_output:
            flag_byte = compressed[i]
            i += 1
            for bit in range(8):
                if i >= chunk_data_end:
                    break
                if not (flag_byte >> bit) & 1:
                    # Literal token: copy one byte verbatim.
                    out.append(compressed[i])
                    i += 1
                else:
                    # Copy token: 2 bytes, split into offset/length by the
                    # current position within the chunk (MS-OVBA 2.4.1.3.19.3).
                    if i + 2 > chunk_data_end:
                        i = chunk_data_end
                        break
                    token = struct.unpack("<H", compressed[i : i + 2])[0]
                    i += 2
                    diff = len(out) - decompressed_chunk_start
                    bit_count = max(4, (diff - 1).bit_length()) if diff > 1 else 4
                    bit_count = min(12, bit_count)
                    length_mask = 0xFFFF >> bit_count
                    offset_mask = ~length_mask & 0xFFFF
                    length = (token & length_mask) + 3
                    offset = ((token & offset_mask) >> (16 - bit_count)) + 1
                    src = len(out) - offset
                    if src < 0:
                        continue
                    for _ in range(length):
                        if len(out) >= max_output:
                            break
                        out.append(out[src])
                        src += 1
    return bytes(out)


def is_vba_module_stream(name: str) -> bool:
    """Heuristic: does this stream path look like a VBA module container?"""
    lname = name.lower()
    return "/vba/" in lname or lname.startswith("vba/")
