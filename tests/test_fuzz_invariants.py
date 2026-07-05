"""In-CI fuzzing: property tests + corpus replay over decoders and analyzers.

These run in the normal pytest suite with a bounded example budget (the
standalone ``fuzz/fuzz_decoders.py`` runner is for longer local/CI fuzzing).
They enforce the safety invariants — never raise uncaught, bounded output,
bounded time — on random/malformed input and on every checked-in corpus seed.

Hypothesis is optional; if it is not installed the property tests are skipped
but the corpus-replay test (which needs no dependency) still runs.
"""

import os
import sys

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from fuzz.invariants import check_all  # noqa: E402

CORPUS_DIR = os.path.join(_ROOT, "fuzz", "corpus")


def _corpus_files():
    if not os.path.isdir(CORPUS_DIR):
        return []
    return [
        os.path.join(CORPUS_DIR, n)
        for n in sorted(os.listdir(CORPUS_DIR))
        if os.path.isfile(os.path.join(CORPUS_DIR, n))
    ]


@pytest.mark.parametrize("path", _corpus_files(), ids=lambda p: os.path.basename(p))
def test_corpus_seed_satisfies_invariants(path):
    data = open(path, "rb").read()
    check_all(data)  # raises InvariantError on any violation


def test_corpus_is_not_empty():
    assert _corpus_files(), "fuzz corpus should have checked-in seeds"


try:
    from hypothesis import given, settings, HealthCheck
    from hypothesis import strategies as st

    _HAS_HYPOTHESIS = True
except Exception:  # pragma: no cover - environment without hypothesis
    _HAS_HYPOTHESIS = False


if _HAS_HYPOTHESIS:

    @settings(
        max_examples=300,
        deadline=None,
        suppress_health_check=[HealthCheck.too_slow],
    )
    @given(st.binary(min_size=0, max_size=4096))
    def test_random_bytes_satisfy_invariants(data):
        check_all(data)

    @settings(max_examples=100, deadline=None)
    @given(
        st.builds(
            lambda prefix, body: prefix + body,
            st.sampled_from(
                [
                    b"%PDF-",
                    b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
                    b"PK\x03\x04",
                    b"MZ",
                    b"\x7fELF",
                    b"\x1f\x8b",
                    b"BZh",
                    b"\xfd7zXZ",
                ]
            ),
            st.binary(min_size=0, max_size=2048),
        )
    )
    def test_magic_prefixed_inputs_satisfy_invariants(data):
        # Inputs that look like a known format but are otherwise garbage stress
        # the structural parsers (CFB/PDF/ZIP/PE/ELF) the hardest.
        check_all(data)
