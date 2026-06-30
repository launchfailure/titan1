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
    # A crafted OLE file full of repeated signatures must not amplify to GBs.
    ole_magic = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
    cap = 5 * 1024 * 1024
    from titan_decoder.decoders.base import OLEDecoder

    for payload in (
        ole_magic + b"Package" * 1_000_000,          # was ~1.1 GB
        ole_magic + (b"MZ" + b"\x00" * 200) * 100000,  # was ~1 GB
    ):
        out, ok = OLEDecoder(cap).decode(payload)
        assert len(out) <= cap


def test_ole_decoder_vba_heavy_is_fast():
    # Repeated VBA markers used to make the end-marker scan O(n^2) (hang).
    import time

    from titan_decoder.decoders.base import OLEDecoder

    payload = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"Attribute VB_Name" * 500000
    start = time.monotonic()
    OLEDecoder(5 * 1024 * 1024).decode(payload)
    assert time.monotonic() - start < 5.0


def test_ole_decoder_extracts_legit_content():
    from titan_decoder.decoders.base import OLEDecoder

    payload = (
        b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
        b"Package\x00 http://evil.com/c2 MZ\x90\x00 payload"
    )
    out, ok = OLEDecoder().decode(payload)
    assert ok and b"evil.com" in out
