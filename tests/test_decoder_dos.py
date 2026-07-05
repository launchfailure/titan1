import time

from titan_decoder.decoders.base import HTMLEntityDecoder, URLDecoder


def test_url_decoder_correctness():
    out, ok = URLDecoder().decode(b"%41%42%43 http%3A%2F%2Fevil.com a+b")
    assert ok and out == b"ABC http://evil.com a b"


def test_html_entity_decoder_correctness():
    out, ok = HTMLEntityDecoder().decode(b"&lt;b&gt; &amp; &#65;&#x42; &quot; &unknownent;")
    assert ok
    assert out == b'<b> & AB " &unknownent;'


def test_url_decoder_linear_on_percent_heavy_input():
    # O(n^2) byte concatenation used to hang on percent-heavy payloads.
    data = b"%41" * 1_000_000  # 3 MB
    start = time.monotonic()
    out, ok = URLDecoder().decode(data)
    assert time.monotonic() - start < 5.0
    assert ok and len(out) == 1_000_000


def test_html_entity_decoder_linear_on_entity_heavy_input():
    # O(n^2) per-char text[i:] slicing used to hang on entity-heavy payloads.
    data = b"&amp;" * 1_000_000  # 5 MB
    start = time.monotonic()
    out, ok = HTMLEntityDecoder().decode(data)
    assert time.monotonic() - start < 5.0
    assert ok and out == b"&" * 1_000_000


def test_ole_decoder_output_is_bounded():
    # A real CFB doc with a large stream must not emit more than the cap.
    import sys
    import os

    sys.path.insert(0, os.path.dirname(__file__))
    from _cfb_fixtures import build_cfb
    from titan_decoder.decoders.base import OLEDecoder

    cap = 512 * 1024
    doc = build_cfb([("Big", b"A" * (4 * 1024 * 1024))])
    out, ok = OLEDecoder(cap).decode(doc)
    assert len(out) <= cap


def test_ole_decoder_garbage_after_magic_is_fast_and_declines():
    # Non-CFB data behind the magic bytes used to be carved into windows; the
    # real parser rejects it fast instead of scanning for markers.
    import time

    from titan_decoder.decoders.base import OLEDecoder

    payload = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"Attribute VB_Name" * 500000
    start = time.monotonic()
    out, ok = OLEDecoder(5 * 1024 * 1024).decode(payload)
    assert time.monotonic() - start < 5.0
    assert ok is False and out == payload


def test_ole_decoder_extracts_legit_stream_content():
    import sys
    import os

    sys.path.insert(0, os.path.dirname(__file__))
    from _cfb_fixtures import build_cfb
    from titan_decoder.decoders.base import OLEDecoder

    doc = build_cfb([("Contents", b"beacon http://evil.com/c2 payload")])
    out, ok = OLEDecoder().decode(doc)
    assert ok and b"evil.com" in out
