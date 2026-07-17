"""Helpers to synthesize minimal Compound File Binary (CFB/OLE2) documents and
MS-OVBA compressed VBA streams for tests.

These build real, structurally-valid CFB files (512-byte sectors) with a
directory tree, so the parser is exercised against actual streams rather than
carved windows. Everything here is synthetic — no real malware.
"""

from __future__ import annotations

import struct
from typing import Dict, List, Tuple

SECTOR = 512
FREESECT = 0xFFFFFFFF
ENDOFCHAIN = 0xFFFFFFFE
FATSECT = 0xFFFFFFFD
NOSTREAM = 0xFFFFFFFF
MINI_CUTOFF = 4096


def compress_ovba(data: bytes) -> bytes:
    """Produce a minimal MS-OVBA CompressedContainer for ``data``.

    Emits compressed chunks whose tokens are all literals (flag byte 0x00 => 8
    literal bytes). An all-literal compressed chunk is always structurally
    valid, which keeps the fixture simple while still exercising the real
    container/chunk/flag/token parsing path in the decompressor.
    """
    out = bytearray([0x01])  # container signature
    for start in range(0, len(data), 4096):
        block = data[start : start + 4096]
        body = bytearray()
        i = 0
        while i < len(block):
            group = block[i : i + 8]
            body.append(0x00)  # all-literal flag byte
            body += group
            i += 8
        chunk_size = len(body) + 2  # includes the 2-byte header itself
        header = ((chunk_size - 3) & 0x0FFF) | (0b011 << 12) | (1 << 15)
        out += struct.pack("<H", header)
        out += body
    return bytes(out)


class _Node:
    def __init__(self, name: str, obj_type: int):
        self.name = name
        self.obj_type = obj_type  # 1 storage, 2 stream, 5 root
        self.children: List["_Node"] = []
        self.content: bytes = b""
        # Filled during layout:
        self.index = -1
        self.left = NOSTREAM
        self.right = NOSTREAM
        self.child = NOSTREAM
        self.start_sector = ENDOFCHAIN
        self.size = 0


def _build_tree(paths: Dict[str, bytes]) -> _Node:
    root = _Node("Root Entry", 5)
    lookup: Dict[Tuple[str, ...], _Node] = {(): root}
    for path, content in paths.items():
        parts = tuple(p for p in path.split("/") if p)
        # Create intermediate storages.
        for depth in range(1, len(parts)):
            key = parts[:depth]
            if key not in lookup:
                node = _Node(parts[depth - 1], 1)
                lookup[key] = node
                lookup[parts[: depth - 1]].children.append(node)
        stream = _Node(parts[-1], 2)
        stream.content = content
        lookup[parts[:-1]].children.append(stream)
        lookup[parts] = stream
    return root


def build_cfb(streams: List[Tuple[str, bytes]]) -> bytes:
    """Build a CFB file from ``(path, content)`` streams.

    Paths may be nested (``Macros/VBA/Module1``); intermediate components become
    storages. Streams are stored in the regular FAT (each padded above the mini
    cutoff to avoid needing a mini stream). Sibling nodes within a storage are
    chained via a right-leaning list, which the parser walks generically.
    """
    root = _build_tree(dict(streams))

    # Assign directory indices in a stable pre-order and wire sibling chains.
    ordered: List[_Node] = []

    def assign(node: _Node) -> None:
        node.index = len(ordered)
        ordered.append(node)
        for child in node.children:
            assign(child)

    assign(root)

    def wire(node: _Node) -> None:
        if node.children:
            node.child = node.children[0].index
            for i, child in enumerate(node.children):
                child.right = (
                    node.children[i + 1].index
                    if i + 1 < len(node.children)
                    else NOSTREAM
                )
                child.left = NOSTREAM
        for child in node.children:
            wire(child)

    wire(root)

    n_entries = len(ordered)
    entries_per_sector = SECTOR // 128
    n_dir_sectors = max(1, (n_entries + entries_per_sector - 1) // entries_per_sector)

    # Streams smaller than the cutoff live in the mini stream (like real CFB
    # files); larger ones live directly in the regular FAT. Build the mini
    # stream first so we know its size, then lay out regular sectors. Sector
    # numbers here are RELATIVE to the start of the data region; a base offset
    # (FAT sectors + directory sectors) is added once the FAT size is known.
    MINI = 64
    mini_stream = bytearray()
    mini_fat: List[int] = []

    small = [n for n in ordered if n.obj_type == 2 and len(n.content) < MINI_CUTOFF]
    large = [n for n in ordered if n.obj_type == 2 and len(n.content) >= MINI_CUTOFF]

    for node in small:
        node.size = len(node.content)
        padded = node.content.ljust(
            ((len(node.content) + MINI - 1) // MINI) * MINI, b"\x00"
        )
        n = max(1, len(padded) // MINI)
        node.start_sector = len(mini_fat)  # mini-sector index (absolute in mini FAT)
        for s in range(n):
            mini_stream += padded[s * MINI : (s + 1) * MINI]
            mini_fat.append(ENDOFCHAIN if s == n - 1 else node.start_sector + s + 1)

    data_sectors: List[bytes] = []
    rel = 0  # relative sector index within the data region

    mini_stream_rel: List[int] = []
    if mini_stream:
        padded_mini = bytes(mini_stream).ljust(
            ((len(mini_stream) + SECTOR - 1) // SECTOR) * SECTOR, b"\x00"
        )
        n = len(padded_mini) // SECTOR
        root.size = len(mini_stream)
        root._rel_start = rel  # type: ignore[attr-defined]
        for s in range(n):
            data_sectors.append(padded_mini[s * SECTOR : (s + 1) * SECTOR])
            mini_stream_rel.append(rel + s)
        rel += n

    minifat_rel: List[int] = []
    if mini_fat:
        minifat_padded = list(mini_fat) + [FREESECT] * (
            ((len(mini_fat) + (SECTOR // 4) - 1) // (SECTOR // 4)) * (SECTOR // 4)
            - len(mini_fat)
        )
        n = len(minifat_padded) // (SECTOR // 4)
        for s in range(n):
            block = minifat_padded[s * (SECTOR // 4) : (s + 1) * (SECTOR // 4)]
            data_sectors.append(struct.pack(f"<{SECTOR // 4}I", *block))
            minifat_rel.append(rel + s)
        rel += n

    for node in large:
        node.size = len(node.content)
        padded = node.content.ljust(
            ((len(node.content) + SECTOR - 1) // SECTOR) * SECTOR, b"\x00"
        )
        n = len(padded) // SECTOR
        node._rel_start = rel  # type: ignore[attr-defined]
        node._n_sectors = n  # type: ignore[attr-defined]
        for s in range(n):
            data_sectors.append(padded[s * SECTOR : (s + 1) * SECTOR])
        rel += n

    data_sector_count = rel

    # Solve for the number of FAT sectors: each addresses SECTOR/4 sectors and
    # the FAT must cover every sector in the file (itself included).
    per_fat = SECTOR // 4
    fat_sector_count = 1
    while fat_sector_count * per_fat < (
        fat_sector_count + n_dir_sectors + data_sector_count
    ):
        fat_sector_count += 1

    base = fat_sector_count + n_dir_sectors
    first_dir_sector = fat_sector_count

    # Shift relative positions to absolute sector numbers.
    mini_stream_sectors = [base + r for r in mini_stream_rel]
    minifat_sectors = [base + r for r in minifat_rel]
    if mini_stream:
        root.start_sector = base + root._rel_start  # type: ignore[attr-defined]
    for node in large:
        node.start_sector = base + node._rel_start  # type: ignore[attr-defined]

    first_minifat_sector = minifat_sectors[0] if minifat_sectors else ENDOFCHAIN
    num_minifat_sectors = len(minifat_sectors)

    # Build FAT (spanning fat_sector_count sectors).
    fat = [FREESECT] * (fat_sector_count * per_fat)
    for s in range(fat_sector_count):
        fat[s] = FATSECT
    for s in range(n_dir_sectors):
        sec = first_dir_sector + s
        fat[sec] = ENDOFCHAIN if s == n_dir_sectors - 1 else sec + 1
    for i, sec in enumerate(mini_stream_sectors):
        fat[sec] = (
            ENDOFCHAIN
            if i == len(mini_stream_sectors) - 1
            else mini_stream_sectors[i + 1]
        )
    for i, sec in enumerate(minifat_sectors):
        fat[sec] = (
            ENDOFCHAIN if i == len(minifat_sectors) - 1 else minifat_sectors[i + 1]
        )
    for node in large:
        n = getattr(node, "_n_sectors", 0)
        for s in range(n):
            sec = node.start_sector + s
            fat[sec] = ENDOFCHAIN if s == n - 1 else sec + 1
    fat_raw = struct.pack(f"<{len(fat)}I", *fat)

    # Build directory sectors.
    dir_raw = bytearray()
    for node in ordered:
        color = 0 if node.obj_type == 5 else 1
        dir_raw += _dir_entry(node, color)
    dir_raw = bytes(dir_raw).ljust(n_dir_sectors * SECTOR, b"\x00")

    # Header.
    header = bytearray(512)
    header[0:8] = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
    struct.pack_into("<H", header, 24, 0x003E)
    struct.pack_into("<H", header, 26, 0x0003)
    struct.pack_into("<H", header, 28, 0xFFFE)
    struct.pack_into("<H", header, 30, 9)  # 512-byte sectors
    struct.pack_into("<H", header, 32, 6)  # 64-byte mini sectors
    struct.pack_into("<I", header, 44, fat_sector_count)
    struct.pack_into("<I", header, 48, first_dir_sector)
    struct.pack_into("<I", header, 56, MINI_CUTOFF)
    struct.pack_into("<I", header, 60, first_minifat_sector)
    struct.pack_into("<I", header, 64, num_minifat_sectors)
    struct.pack_into("<I", header, 68, ENDOFCHAIN)  # first difat
    struct.pack_into("<I", header, 72, 0)
    # DIFAT header array references the first 109 FAT sectors (more than enough
    # for tests, which never approach 109 FAT sectors).
    difat = [FREESECT] * 109
    for s in range(min(fat_sector_count, 109)):
        difat[s] = s
    struct.pack_into("<109I", header, 76, *difat)

    return bytes(header) + fat_raw + dir_raw + b"".join(data_sectors)


def _dir_entry(node: _Node, color: int) -> bytes:
    name_utf16 = node.name.encode("utf-16-le")
    name_field = (name_utf16 + b"\x00\x00")[:64].ljust(64, b"\x00")
    name_len = min(len(name_utf16) + 2, 64)
    entry = bytearray(128)
    entry[0:64] = name_field
    struct.pack_into("<H", entry, 64, name_len)
    entry[66] = node.obj_type
    entry[67] = color
    struct.pack_into("<I", entry, 68, node.left)
    struct.pack_into("<I", entry, 72, node.right)
    struct.pack_into("<I", entry, 76, node.child)
    struct.pack_into("<I", entry, 116, node.start_sector)
    struct.pack_into("<I", entry, 120, node.size & 0xFFFFFFFF)
    struct.pack_into("<I", entry, 124, (node.size >> 32) & 0xFFFFFFFF)
    return bytes(entry)


def build_vba_doc(module_name: str, vba_source: bytes) -> bytes:
    """Build a CFB doc with a VBA module at path ``Macros/VBA/<module_name>``.

    The module stream carries a small binary prefix before the MS-OVBA
    container, so the decoder must locate the ``0x01`` container signature
    rather than assume the source starts at offset 0 (as real module streams do,
    where a performance cache precedes the compressed source).
    """
    compressed = compress_ovba(vba_source)
    prefix = b"\xde\xad\xbe\xef\x00\x00"
    stream = prefix + compressed
    return build_cfb([(f"Macros/VBA/{module_name}", stream)])
