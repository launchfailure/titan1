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
