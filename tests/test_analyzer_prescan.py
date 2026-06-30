"""Regression tests for archive pre-scan complexity and size caps.

ZipAnalyzer._pre_scan_zip / TarAnalyzer._pre_scan_tar previously recomputed the
running total size with ``sum(... for f in safe_files)`` on every iteration,
making the scan O(n^2). A small crafted archive with many tiny entries (which
never trip the total-size cap, so the safe list keeps growing) turned pre-scan
into a multi-minute CPU hang — an algorithmic-complexity DoS reachable from
untrusted input. The fix tracks the total incrementally (O(n)).
"""

import io
import os
import hashlib
import time
import zipfile
import tarfile

from titan_decoder.core.analyzers.base import ZipAnalyzer, TarAnalyzer


def _zip_of_empty(n: int) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        for i in range(n):
            z.writestr(f"f{i}", b"")
    return buf.getvalue()


def _tar_of_empty(n: int) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        for i in range(n):
            ti = tarfile.TarInfo(f"f{i}")
            ti.size = 0
            t.addfile(ti)
    return buf.getvalue()


def test_zip_prescan_many_tiny_entries_is_not_quadratic():
    # At O(n^2) this took ~30s+; O(n) finishes in well under the bound.
    data = _zip_of_empty(20000)
    t0 = time.time()
    out = ZipAnalyzer().analyze(data)
    assert time.time() - t0 < 15.0
    assert len(out) <= 25  # max_zip_files cap still applies


def test_tar_prescan_many_tiny_entries_is_not_quadratic():
    data = _tar_of_empty(20000)
    t0 = time.time()
    out = TarAnalyzer().analyze(data)
    assert time.time() - t0 < 15.0
    assert len(out) <= 25


def test_zip_total_size_cap_still_honored():
    files = [(f"file_{i}.bin", os.urandom(8000)) for i in range(40)]
    expected = {nm: hashlib.sha256(c).hexdigest() for nm, c in files}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for nm, c in files:
            z.writestr(nm, c)
    # ~100KB total cap -> only ~12 of the 8KB files fit.
    out = ZipAnalyzer({"max_zip_total_size": 100 * 1024, "max_zip_files": 100}).analyze(
        buf.getvalue()
    )
    total = sum(len(c) for _, c in out)
    assert total <= 100 * 1024 + 8000  # cap, plus at most one boundary-crossing file
    # whatever was extracted must be byte-correct (no corruption)
    for nm, c in out:
        assert expected[nm] == hashlib.sha256(c).hexdigest()
