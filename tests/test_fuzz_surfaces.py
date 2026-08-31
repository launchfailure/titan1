from pathlib import Path

import pytest

from fuzz.fuzz_surfaces import minimize_failure
from fuzz.surface_invariants import SurfaceInvariantError, check_surfaces
from titan_decoder.server.app import parse_artifact_length


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"\x00\xffnot-json\r\n",
        b'{"nodes":[],"iocs":{},"timeline":[]}',
        b'{"context":{"max_input_bytes":"bad"},"payload":{"data":"%%%"}}',
    ],
)
def test_cross_surface_invariants_accept_or_reject_hostile_bytes_safely(data, tmp_path):
    check_surfaces(data, tmp_path)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("1", 1),
        ("4096", 4096),
        (None, None),
        ("", None),
        ("-1", None),
        ("4097", None),
        ("9" * 5000, None),
    ],
)
def test_server_request_length_parser_is_total_and_bounded(value, expected):
    assert parse_artifact_length(value, 4096) == expected


def test_failure_minimizer_preserves_surface(monkeypatch, tmp_path):
    def fake_check(data: bytes, _root: Path) -> None:
        if b"CRASH" in data:
            raise SurfaceInvariantError("fake", "unexpected-exception", "boom")

    monkeypatch.setattr("fuzz.fuzz_surfaces.check_surfaces", fake_check)

    minimized = minimize_failure(
        b"prefix-CRASH-suffix", tmp_path, "fake", "unexpected-exception"
    )

    assert minimized == b"CRASH"
