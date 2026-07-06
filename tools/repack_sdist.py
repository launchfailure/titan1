#!/usr/bin/env python3
"""Deterministically repack an sdist tarball for reproducible builds.

The supply-chain contract (docs/SUPPLY_CHAIN.md) is that two independent
builders produce byte-identical artifacts. The wheel already holds: bdist_wheel
honors SOURCE_DATE_EPOCH. The sdist does not — setuptools writes each tar
member with its *filesystem* mtime (at sub-second precision, via PAX records),
which encodes the moment the build host checked out or generated the file, so
every build differs.

This tool rewrites an sdist tar.gz with normalized metadata:

- member mtimes set to SOURCE_DATE_EPOCH (integer seconds, so no float PAX
  mtime records are emitted)
- uid/gid 0 and uname/gname "root" (setuptools' own convention)
- mode 0755 for directories and owner-executable files, 0644 otherwise
- members sorted by path
- gzip container written with mtime=0 and no embedded filename

File contents are preserved exactly: the repack verifies the rewritten
archive against the original member-for-member and refuses to replace the
file on any mismatch.

Usage:

    SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct) \\
        python tools/repack_sdist.py dist/*.tar.gz

If SOURCE_DATE_EPOCH is unset, the last git commit time is used.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import os
import subprocess
import sys
import tarfile


def source_date_epoch() -> int:
    env = os.environ.get("SOURCE_DATE_EPOCH")
    if env is not None:
        return int(env)
    out = subprocess.run(
        ["git", "log", "-1", "--pretty=%ct"],
        capture_output=True,
        text=True,
        check=True,
        cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    )
    return int(out.stdout.strip())


def _read_members(path: str) -> list[tuple[tarfile.TarInfo, bytes | None]]:
    members: list[tuple[tarfile.TarInfo, bytes | None]] = []
    with tarfile.open(path, "r:gz") as tf:
        for info in tf.getmembers():
            if info.isreg():
                fobj = tf.extractfile(info)
                assert fobj is not None
                members.append((info, fobj.read()))
            elif info.isdir():
                members.append((info, None))
            else:
                raise ValueError(
                    f"{path}: unsupported member type {info.type!r} for "
                    f"{info.name!r}; refusing to repack"
                )
    return members


def repack_bytes(
    members: list[tuple[tarfile.TarInfo, bytes | None]], epoch: int
) -> bytes:
    """Serialize members into a deterministic tar.gz byte string."""
    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w", format=tarfile.PAX_FORMAT) as tf:
        for info, data in sorted(members, key=lambda m: m[0].name):
            norm = tarfile.TarInfo(info.name)
            norm.type = info.type
            norm.size = info.size
            norm.mtime = epoch
            norm.uid = norm.gid = 0
            norm.uname = norm.gname = "root"
            executable = info.isdir() or (info.mode & 0o100)
            norm.mode = 0o755 if executable else 0o644
            tf.addfile(norm, io.BytesIO(data) if data is not None else None)

    gz_buf = io.BytesIO()
    with gzip.GzipFile(fileobj=gz_buf, mode="wb", compresslevel=9, mtime=0) as gz:
        gz.write(tar_buf.getvalue())
    return gz_buf.getvalue()


def _verify(original: list[tuple[tarfile.TarInfo, bytes | None]], new: bytes) -> None:
    rewritten: dict[str, bytes | None] = {}
    with tarfile.open(fileobj=io.BytesIO(new), mode="r:gz") as tf:
        for info in tf.getmembers():
            fobj = tf.extractfile(info) if info.isreg() else None
            rewritten[info.name] = fobj.read() if fobj is not None else None
    expected = {info.name: data for info, data in original}
    if rewritten != expected:
        raise RuntimeError("repacked archive does not match original contents")


def repack(path: str, epoch: int) -> tuple[str, str]:
    """Rewrite *path* in place; returns (old_sha256, new_sha256)."""
    with open(path, "rb") as f:
        old_digest = hashlib.sha256(f.read()).hexdigest()

    members = _read_members(path)
    new_bytes = repack_bytes(members, epoch)
    _verify(members, new_bytes)

    tmp = path + ".repack.tmp"
    with open(tmp, "wb") as f:
        f.write(new_bytes)
    os.replace(tmp, path)
    return old_digest, hashlib.sha256(new_bytes).hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("paths", nargs="+", help="sdist .tar.gz file(s) to repack")
    parser.add_argument(
        "--epoch",
        type=int,
        default=None,
        help="timestamp override (default: $SOURCE_DATE_EPOCH, else last commit time)",
    )
    args = parser.parse_args(argv)

    epoch = args.epoch if args.epoch is not None else source_date_epoch()
    for path in args.paths:
        old, new = repack(path, epoch)
        status = "unchanged" if old == new else "normalized"
        print(f"{path}: {status}\n  sha256 {new}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
