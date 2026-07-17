"""Reproducible-sdist repack tests (tools/repack_sdist.py).

setuptools writes sdist tar members with filesystem mtimes, so two otherwise
identical builds differ. The repack tool must erase exactly that variance —
and nothing else: contents byte-identical, unsupported members refused.
"""

import io
import os
import sys
import tarfile

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from tools.repack_sdist import repack, repack_bytes, _read_members  # noqa: E402

EPOCH = 1700000000


def _make_sdist(path, mtime, order=None):
    """Simulate a setuptools sdist: PAX format, float mtimes, root/root."""
    files = {
        "pkg-1.0/PKG-INFO": b"Metadata-Version: 2.4\nName: pkg\n",
        "pkg-1.0/pkg/__init__.py": b"__version__ = '1.0'\n",
        "pkg-1.0/setup.cfg": b"[metadata]\n",
    }
    names = order or sorted(files)
    with tarfile.open(path, "w:gz", format=tarfile.PAX_FORMAT) as tf:
        dirinfo = tarfile.TarInfo("pkg-1.0/")
        dirinfo.type = tarfile.DIRTYPE
        dirinfo.mode = 0o755
        dirinfo.mtime = mtime
        tf.addfile(dirinfo)
        for name in names:
            info = tarfile.TarInfo(name)
            info.size = len(files[name])
            info.mtime = mtime
            tf.addfile(info, io.BytesIO(files[name]))
    return files


def test_two_builds_repack_byte_identical(tmp_path):
    """Different build times and member order must converge to one byte string."""
    a, b = tmp_path / "a.tar.gz", tmp_path / "b.tar.gz"
    _make_sdist(a, mtime=1750000000.1234567)
    _make_sdist(
        b,
        mtime=1760000000.7654321,
        order=[
            "pkg-1.0/setup.cfg",
            "pkg-1.0/PKG-INFO",
            "pkg-1.0/pkg/__init__.py",
        ],
    )
    assert a.read_bytes() != b.read_bytes()

    repack(str(a), EPOCH)
    repack(str(b), EPOCH)
    assert a.read_bytes() == b.read_bytes()


def test_repack_is_idempotent_and_preserves_contents(tmp_path):
    path = tmp_path / "s.tar.gz"
    files = _make_sdist(path, mtime=1750000000.5)

    repack(str(path), EPOCH)
    first = path.read_bytes()
    repack(str(path), EPOCH)
    assert path.read_bytes() == first

    with tarfile.open(path, "r:gz") as tf:
        for name, data in files.items():
            assert tf.extractfile(name).read() == data


def test_metadata_normalized(tmp_path):
    path = tmp_path / "s.tar.gz"
    _make_sdist(path, mtime=1750000000.5)
    repack(str(path), EPOCH)

    # gzip container: mtime field zeroed (bytes 4-8 of the header).
    raw = path.read_bytes()
    assert raw[4:8] == b"\x00\x00\x00\x00"

    with tarfile.open(path, "r:gz") as tf:
        members = tf.getmembers()
        assert [m.name for m in members] == sorted(m.name for m in members)
        for m in members:
            assert m.mtime == EPOCH
            assert (m.uid, m.gid, m.uname, m.gname) == (0, 0, "root", "root")
            assert m.mode == (0o755 if m.isdir() else 0o644)


def test_refuses_unsupported_member_types(tmp_path):
    path = tmp_path / "s.tar.gz"
    with tarfile.open(path, "w:gz") as tf:
        link = tarfile.TarInfo("pkg-1.0/evil")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/passwd"
        tf.addfile(link)
    with pytest.raises(ValueError, match="unsupported member type"):
        repack(str(path), EPOCH)


def test_verify_catches_content_corruption(tmp_path, monkeypatch):
    """The self-check must fail closed if the rewrite ever altered contents."""
    path = tmp_path / "s.tar.gz"
    _make_sdist(path, mtime=1750000000.5)
    members = _read_members(str(path))
    original = path.read_bytes()

    corrupted = [
        (info, data.replace(b"1.0", b"6.6") if data else data) for info, data in members
    ]
    monkeypatch.setattr(
        "tools.repack_sdist.repack_bytes",
        lambda _members, epoch: repack_bytes(corrupted, epoch),
    )
    with pytest.raises(RuntimeError, match="does not match original"):
        repack(str(path), EPOCH)
    assert path.read_bytes() == original  # file left untouched
