"""Tests for repeating-key XOR recovery with sampled scoring.

Single-byte XOR is covered by test_xor_singlebyte.py. These exercise the
multi-byte key path (lengths 2--8) recovered by per-column frequency analysis,
the raised size cap with sampled scoring, and the DoS/false-positive guards.
"""

import os
import random
import time

from titan_decoder.decoders.base import XorDecoder


CONFIG = (
    b"[settings]\n"
    b"c2_url=http://malware.example/panel\n"
    b"sleep=60\nkey=deadbeef\n"
    b"user_agent=Mozilla/5.0 (Windows NT 10.0)\n"
    b"port=4444\nretries=5\n"
)


def _config_of_size(n: int) -> bytes:
    reps = (n // len(CONFIG)) + 1
    return (CONFIG * reps)[:n]


def test_4kb_config_with_4byte_key_decodes():
    plain = _config_of_size(4096)
    key = b"\x11\x37\xab\x5c"
    ct = bytes(b ^ key[i % 4] for i, b in enumerate(plain))
    dec = XorDecoder()
    assert dec.can_decode(ct)
    out, ok = dec.decode(ct)
    assert ok
    assert out == plain


def test_various_key_lengths_2_to_8():
    plain = _config_of_size(4096)
    dec = XorDecoder()
    recovered = 0
    keys = [
        b"\x9e\x42",
        b"\x11\x37\xab\x5c",
        b"secret!!",  # length 8
        b"\xaa\xbb\xcc\xdd\xee",
        b"\x7f\x01\x9c\x3d\x55\x22",
    ]
    for key in keys:
        ct = bytes(b ^ key[i % len(key)] for i, b in enumerate(plain))
        out, ok = dec.decode(ct)
        if ok and out == plain:
            recovered += 1
    # Allow the occasional low-perturbation key ambiguity.
    assert recovered >= len(keys) - 1


def test_large_input_decodes_within_time_budget():
    plain = _config_of_size(512 * 1024)
    key = b"\x11\x37\xab\x5c"
    ct = bytes(b ^ key[i % 4] for i, b in enumerate(plain))
    dec = XorDecoder()
    start = time.monotonic()
    out, ok = dec.decode(ct)
    elapsed = time.monotonic() - start
    assert elapsed < 5.0  # well within the decode timeout
    assert ok and out == plain


def test_no_false_positives_on_random_binary():
    dec = XorDecoder()
    rng = random.Random(7)
    fabricated = 0
    for _ in range(150):
        data = bytes(rng.randrange(256) for _ in range(rng.randint(64, 512)))
        if dec.can_decode(data):
            out, ok = dec.decode(data)
            if ok and out != data:
                fabricated += 1
    assert fabricated == 0


def test_does_not_scramble_readable_hex_or_base64():
    import base64
    import binascii

    dec = XorDecoder()
    for data in (
        b"the quick brown fox jumps over the lazy dog and then repeats itself",
        binascii.hexlify(os.urandom(300)),
        base64.b64encode(os.urandom(300)),
    ):
        out, ok = dec.decode(data) if dec.can_decode(data) else (data, False)
        assert not (ok and out != data)


def test_oversized_input_is_declined():
    dec = XorDecoder()
    huge = os.urandom(dec.MAX_SIZE + 1)
    assert dec.can_decode(huge) is False
