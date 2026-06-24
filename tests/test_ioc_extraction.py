import hashlib

from titan_decoder.utils.helpers import extract_iocs


def test_hash_ioc_only_matches_real_digest_lengths():
    # Real hash digest lengths should be detected.
    for algo in ("md5", "sha1", "sha224", "sha256", "sha384", "sha512"):
        digest = hashlib.new(algo, b"sample").hexdigest()
        assert digest in extract_iocs(f"file {digest} seen")["hashes"], algo


def test_hash_ioc_ignores_non_standard_hex_runs():
    # Hex-encoded payloads / arbitrary hex runs of non-hash length must not be
    # reported as hash IOCs.
    hex_text = "48656c6c6f20576f726c6420746573740a"  # 34 chars: hex of "Hello World test\n"
    assert extract_iocs(hex_text)["hashes"] == []

    for length in (31, 33, 34, 39, 41, 50, 63, 65, 95, 127):
        run = "a" * length
        assert extract_iocs(f"id={run}")["hashes"] == [], length
