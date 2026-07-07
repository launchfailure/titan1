"""Tests for the interactive menu-driven UI (``titan`` command).

The UI is a thin presentation layer over the engine/decoders, so these tests
drive the loop with injected input/output streams (no real TTY) and assert the
observable behavior: the right decoder runs, results render, and bad input is
handled without crashing the loop.
"""

import base64
import io

from titan_decoder.interactive import (
    InteractiveApp,
    Style,
    build_decoder_registry,
    format_decode_result,
    _hexdump,
)


def _run(script):
    """Drive the app with a scripted list of input lines; return stdout text."""
    it = iter(script)

    def fake_input(prompt=""):
        return next(it)

    out = io.StringIO()
    app = InteractiveApp(input_fn=fake_input, out=out, style=Style(False))
    rc = app.run()
    return rc, out.getvalue()


def test_registry_has_expected_decoders():
    reg = build_decoder_registry()
    keys = {c.key for c in reg}
    # A representative spread across the decoder families.
    for expected in ("base64", "hex", "url", "rot13", "xor", "gzip", "utf16"):
        assert expected in keys
    # Every entry's factory yields a working decoder instance.
    for choice in reg:
        dec = choice.factory()
        assert hasattr(dec, "decode")
        assert dec.name


def test_specific_decoder_base64_roundtrip():
    payload = base64.b64encode(b"Hello Titan!").decode()
    # menu=2 (pick decoder), decoder=1 (Base64), input=1 (text), payload,
    # ""=skip the save prompt, quit
    rc, text = _run(["2", "1", "1", payload, "", "q"])
    assert rc == 0
    assert "Decoded with Base64" in text
    assert "Hello Titan!" in text


def test_specific_decoder_reports_failure_cleanly():
    # Base64 decoder on clearly non-base64 bytes should report a clean failure,
    # not raise or exit the loop.
    rc, text = _run(["2", "1", "1", "!!! not base64 !!!", "q"])
    assert rc == 0
    assert "could not decode" in text


def test_hex_input_mode():
    # Hex *input mode* (2) turns "48656c6c6f" into b"Hello", then we Base64 it.
    # Trailing "" safely skips the save prompt whether the decode succeeds or not.
    rc, text = _run(["2", "1", "2", "48656c6c6f", "", "q"])  # Base64 on b"Hello"
    assert rc == 0
    # b"Hello" is not valid base64 padding-wise -> clean failure is fine; the
    # point is the hex input mode parsed without crashing.
    assert "Base64" in text


def test_hex_input_mode_rejects_bad_hex():
    rc, text = _run(["2", "5", "2", "zzzz", "q"])  # Hex decoder, bad hex input
    assert rc == 0
    assert "Not valid hex" in text


def test_auto_detect_extracts_iocs():
    payload = base64.b64encode(b"beacon to http://evil.example.com/c2").decode()
    # auto-detect, text input, ""=skip the "save report" prompt, quit
    rc, text = _run(["1", "1", payload, "", "q"])
    assert rc == 0
    assert "Auto-analysis complete" in text
    assert "evil.example.com" in text


def test_save_decoded_output_to_file(tmp_path):
    out_file = tmp_path / "decoded.bin"
    payload = base64.b64encode(b"Hello Titan!").decode()
    # decode Base64, then save the decoded bytes to out_file
    rc, text = _run(["2", "1", "1", payload, str(out_file), "q"])
    assert rc == 0
    assert "Saved" in text
    assert out_file.read_bytes() == b"Hello Titan!"


def test_save_creates_missing_parent_dirs(tmp_path):
    out_file = tmp_path / "nested" / "sub" / "out.bin"
    plain = b"deep enough to pass base64 detection"
    payload = base64.b64encode(plain).decode()
    rc, text = _run(["2", "1", "1", payload, str(out_file), "q"])
    assert rc == 0
    assert out_file.read_bytes() == plain


def test_save_report_json(tmp_path):
    report_file = tmp_path / "report.json"
    payload = base64.b64encode(b"see http://evil.example.com/x").decode()
    rc, text = _run(["1", "1", payload, str(report_file), "q"])
    assert rc == 0
    assert report_file.exists()
    import json as _json

    data = _json.loads(report_file.read_text())
    assert "nodes" in data and "iocs" in data


def test_list_decoders_action():
    rc, text = _run(["3", "q"])
    assert rc == 0
    assert "decoders available" in text
    assert "Base64" in text


def test_options_change_profile():
    # Open options, set profile to full, back, then quit; the menu should now
    # reflect the new profile.
    rc, text = _run(["4", "1", "full", "b", "q"])
    assert rc == 0
    assert "profile=full" in text


def test_eof_quits_gracefully():
    # A StopIteration from the scripted input surfaces as EOFError-like; feed a
    # real EOF by exhausting the script mid-prompt.
    def eof_input(prompt=""):
        raise EOFError

    out = io.StringIO()
    app = InteractiveApp(input_fn=eof_input, out=out, style=Style(False))
    assert app.run() == 0
    assert "Bye." in out.getvalue()


def test_hexdump_format():
    dump = _hexdump(b"ABC\x00\xff")
    assert "00000000" in dump
    assert "41 42 43 00 ff" in dump
    # Printable ASCII shown, non-printable as dots.
    assert "ABC.." in dump


def test_format_decode_result_binary_uses_hexdump():
    st = Style(False)
    out = format_decode_result(st, "Gzip", 10, b"\x00\x01\x02\x03\xff\xfe", True)
    assert "hexdump" in out.lower()


def test_style_disabled_has_no_ansi():
    st = Style(False)
    assert st.red("x") == "x"
    st2 = Style(True)
    assert "\033[" in st2.red("x")
