"""Minimal synthetic PDF builders for exercising the object-graph parser.

These build small but structurally valid PDFs with cross-referenced indirect
objects and object streams (``/Type /ObjStm``). Everything is synthetic.
"""

from __future__ import annotations

import zlib
from typing import List, Tuple


def build_pdf(objects: List[Tuple[int, bytes]], root_ref: str = "1 0 R") -> bytes:
    """Assemble a PDF from ``(object_number, body_bytes)`` pairs.

    ``body_bytes`` is the full ``... `` content between ``obj`` and ``endobj``
    (may include a ``stream``/``endstream`` block). A trailer and ``%%EOF`` are
    appended; the xref is intentionally minimal (the parser brute-force scans
    objects, so a byte-accurate xref is not required for these tests).
    """
    out = bytearray(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
    offsets = {}
    for num, body in objects:
        offsets[num] = len(out)
        out += f"{num} 0 obj\n".encode()
        out += body
        out += b"\nendobj\n"
    xref_pos = len(out)
    out += b"xref\n0 1\n0000000000 65535 f \n"
    out += f"trailer\n<< /Root {root_ref} >>\nstartxref\n{xref_pos}\n".encode()
    out += b"%%EOF\n"
    return bytes(out)


def flate_stream(dict_extra: bytes, payload: bytes) -> bytes:
    """Build a stream object body with FlateDecode-compressed ``payload``."""
    comp = zlib.compress(payload)
    d = (
        b"<< /Length "
        + str(len(comp)).encode()
        + b" /Filter /FlateDecode "
        + dict_extra
        + b" >>"
    )
    return d + b"\nstream\n" + comp + b"\nendstream"


def build_objstm_pdf(packed_objects: List[Tuple[int, bytes]]) -> bytes:
    """Build a PDF where ``packed_objects`` live inside a /Type /ObjStm stream.

    Each packed object is ``(object_number, object_text)`` where object_text is
    the raw object value (no ``N G obj`` wrapper). These objects appear nowhere
    as ``N G obj`` in the file, so only an ObjStm-aware parser can see them.
    """
    header = b""
    body = b""
    offsets = []
    for num, text in packed_objects:
        offsets.append((num, len(body)))
        body += text + b" "
    header = b" ".join(f"{num} {off}".encode() for num, off in offsets) + b" "
    first = len(header)
    content = header + body
    comp = zlib.compress(content)
    objstm_body = (
        b"<< /Type /ObjStm /N "
        + str(len(packed_objects)).encode()
        + b" /First "
        + str(first).encode()
        + b" /Length "
        + str(len(comp)).encode()
        + b" /Filter /FlateDecode >>\nstream\n"
        + comp
        + b"\nendstream"
    )
    return build_pdf([(1, b"<< /Type /Catalog >>"), (10, objstm_body)])
