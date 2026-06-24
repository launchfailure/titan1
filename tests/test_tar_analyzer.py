import io
import os
import tarfile

from titan_decoder.core.analyzers.base import TarAnalyzer


def _make_tar(fmt, name="evil.txt", content=b"http://bad.com 8.8.8.8"):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=fmt) as t:
        info = tarfile.TarInfo(name)
        info.size = len(content)
        t.addfile(info, io.BytesIO(content))
    return buf.getvalue()


def test_can_analyze_all_tar_formats():
    # GNU format (common default of `tar`) uses "ustar  " magic; POSIX/PAX use
    # "ustar\x00". Both must be detected.
    for fmt in (tarfile.USTAR_FORMAT, tarfile.GNU_FORMAT, tarfile.PAX_FORMAT):
        assert TarAnalyzer().can_analyze(_make_tar(fmt)) is True


def test_can_analyze_rejects_non_tar():
    assert TarAnalyzer().can_analyze(b"ustar") is False  # too short
    assert TarAnalyzer().can_analyze(os.urandom(600)) is False


def test_gnu_tar_contents_extracted():
    extracted = TarAnalyzer().analyze(_make_tar(tarfile.GNU_FORMAT))
    assert len(extracted) == 1
    name, content = extracted[0]
    assert b"http://bad.com" in content
