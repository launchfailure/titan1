"""Synthetic labeled corpus for detection-rule evaluation.

Every sample here is generated from documentation-range, synthetic bytes — no
real malware is stored in the repository (per the roadmap: "commit the harness,
not the malware"). Each sample carries a ground-truth label: whether it is
"malicious" (should raise the overall risk) and which built-in detection rule
IDs (TITAN-00N) are *expected* to fire. The evaluator compares fired vs.
expected to compute per-rule precision/recall.

The benign samples are ordinary clean files (text config, JSON, a plain PDF, a
single non-nested base64 blob) that a analyst would see constantly; they anchor
the false-positive measurement.
"""

from __future__ import annotations

import base64
import io
import os
import random
import sys
import zlib
import zipfile
from dataclasses import dataclass, field
from typing import List, Set

# Reuse the synthetic CFB / PDF builders from the test fixtures. This harness is
# a developer tool (not shipped in the package), so importing test helpers is
# fine and keeps the builders DRY.
_TESTS = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tests"
)
if _TESTS not in sys.path:
    sys.path.insert(0, _TESTS)

from _cfb_fixtures import build_cfb  # noqa: E402
from _pdf_fixtures import build_pdf, flate_stream  # noqa: E402


@dataclass
class Sample:
    name: str
    data: bytes
    malicious: bool
    expected_rules: Set[str] = field(default_factory=set)


def _nested_base64(payload: bytes, layers: int) -> bytes:
    out = payload
    for _ in range(layers):
        out = base64.b64encode(out)
    return out


def _png_with_appended(payload: bytes = b"") -> bytes:
    def chunk(kind: bytes, value: bytes) -> bytes:
        body = kind + value
        return (
            len(value).to_bytes(4, "big")
            + body
            + (zlib.crc32(body) & 0xFFFFFFFF).to_bytes(4, "big")
        )

    ihdr = b"\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00"
    image = (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", zlib.compress(b"\x00\x80\x80\x80"))
        + chunk(b"IEND", b"")
    )
    return image + payload


def _rtf_object(payload: bytes, object_controls: bytes = b"\\objemb") -> bytes:
    return (
        b"{\\rtf1\\ansi Delivery document\\par "
        b"{\\object"
        + object_controls
        + b"{\\*\\objclass Package}{\\*\\objdata "
        + payload.hex().encode("ascii")
        + b"}}}"
    )


def _xlm_workbook(formula: str, *, macro_sheet: bool = True) -> bytes:
    output = io.BytesIO()
    member = "xl/macrosheets/sheet1.xml" if macro_sheet else "xl/worksheets/sheet1.xml"

    def write(archive: zipfile.ZipFile, name: str, value: str) -> None:
        info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        archive.writestr(info, value)

    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        write(
            archive,
            "[Content_Types].xml",
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>',
        )
        write(archive, "xl/workbook.xml", "<workbook/>")
        write(
            archive,
            member,
            f'<worksheet><sheetData><c r="A1"><f>{formula}</f>'
            "<v>0</v></c></sheetData></worksheet>",
        )
    return output.getvalue()


def _msi_package(strings: list[str], payload: bytes | None = None) -> bytes:
    encoded = [value.encode("cp1252") for value in strings]
    pool = (
        (1252).to_bytes(2, "little")
        + b"\x00\x00"
        + b"".join(len(value).to_bytes(2, "little") + b"\x01\x00" for value in encoded)
    )
    streams = [("_StringPool", pool), ("_StringData", b"".join(encoded))]
    if payload is not None:
        streams.append(("Binary/Updater", payload))
    return build_cfb(streams)


def _onenote_section(payloads: list[bytes]) -> bytes:
    file_type = bytes.fromhex("e4525c7b8cd8a74daeb15378d02996d3")
    revision_format = bytes.fromhex("3fdd9a101b91f549a5d01791edc8aed8")
    object_header = bytes.fromhex("e716e3bd65261145a4c48d4d0b7a9eac")
    object_footer = bytes.fromhex("22a7fb71790f0b4abb13899256426b24")
    header = bytearray(1024)
    header[:16] = file_type
    header[48:64] = revision_format
    output = bytearray(header)
    for payload in payloads:
        output += object_header
        output += len(payload).to_bytes(8, "little")
        output += b"\x00" * 12
        output += payload
        output += b"\x00" * (-(52 + len(payload)) % 8)
        output += object_footer
    return bytes(output)


def build_corpus() -> List[Sample]:
    samples: List[Sample] = []

    # --- Malicious samples --------------------------------------------------

    # TITAN-001: deep base64 nesting (3+ layers) around a C2 URL.
    samples.append(
        Sample(
            "mal_deep_base64",
            _nested_base64(b"beacon to http://malware.example/c2/panel now", 4),
            malicious=True,
            expected_rules={"TITAN-001"},
        )
    )

    # TITAN-002: Office/CFB macro doc with a network IOC in the stream.
    vba = (
        b'Attribute VB_Name = "Module1"\r\n'
        b"Sub AutoOpen()\r\n"
        b'  MsgBox "http://malware.example/office-c2"\r\n'
        b"End Sub\r\n"
    )
    samples.append(
        Sample(
            "mal_office_macro",
            build_cfb([("Macros/VBA/Module1", vba)]),
            malicious=True,
            expected_rules={"TITAN-002"},
        )
    )

    # TITAN-003: LOLBin execution pattern.
    samples.append(
        Sample(
            "mal_lolbin",
            b"powershell -NoProfile -EncodedCommand SQBFAFgA ; cmd.exe /c whoami",
            malicious=True,
            expected_rules={"TITAN-003"},
        )
    )

    # TITAN-004: encrypted/packed payload — high entropy, few decodes. Seeded
    # (not os.urandom) so the evaluation is deterministic and the committed
    # metrics are reproducible.
    samples.append(
        Sample(
            "mal_packed",
            random.Random(0x5EED).randbytes(2048),
            malicious=True,
            expected_rules={"TITAN-004"},
        )
    )

    # TITAN-005: multi-stage infrastructure — 3+ IOC types.
    samples.append(
        Sample(
            "mal_multistage",
            (
                b"c2 http://malware.example/gate.php\n"
                b"fallback 203.0.113.45\n"
                b"panel evil.example.org\n"
                b"contact operator@evil.example\n"
            ),
            malicious=True,
            expected_rules={"TITAN-005"},
        )
    )

    # TITAN-006: XOR-obfuscated C2 URL (single-byte key).
    plain = b"config c2=http://malware.example/xor-c2/beacon endpoint here"
    samples.append(
        Sample(
            "mal_xor_c2",
            bytes(b ^ 0x5A for b in plain),
            malicious=True,
            expected_rules={"TITAN-006"},
        )
    )

    # TITAN-007: PDF carrying an embedded PE (MZ) via a stream.
    mz_payload = (
        b"MZ\x90\x00" + b"\x00" * 200 + b"This program cannot be run in DOS mode"
    )
    pdf = build_pdf(
        [
            (1, b"<< /Type /Catalog /OpenAction 3 0 R >>"),
            (3, b"<< /S /JavaScript /JS 5 0 R >>"),
            (5, flate_stream(b"", mz_payload)),
        ]
    )
    samples.append(
        Sample(
            "mal_pdf_pe",
            pdf,
            malicious=True,
            expected_rules={"TITAN-007"},
        )
    )

    # TITAN-008: executable appended after a valid PNG end marker.
    samples.append(
        Sample(
            "mal_hidden_media_pe",
            _png_with_appended(b"MZ hidden executable payload"),
            malicious=True,
            expected_rules={"TITAN-008"},
        )
    )

    # TITAN-009: RTF with a carved executable that contains network delivery
    # infrastructure. Plain hyperlinks and passive attachments are negatives.
    samples.append(
        Sample(
            "mal_rtf_embedded_executable",
            _rtf_object(b"MZ http://rtf-c2.example/payload"),
            malicious=True,
            expected_rules={"TITAN-009"},
        )
    )

    # TITAN-010: Excel 4.0 macro sheet invokes an execution function.
    samples.append(
        Sample(
            "mal_xlm_exec",
            _xlm_workbook('=EXEC("calc.exe")'),
            malicious=True,
            expected_rules={"TITAN-010"},
        )
    )

    # TITAN-011: an MSI database combines an executable payload with network
    # infrastructure recovered from its string table and payload.
    samples.append(
        Sample(
            "mal_msi_executable_delivery",
            _msi_package(
                ["ProductName", "https://updates.msi-evil.example/stage"],
                b"MZ bounded synthetic executable",
            ),
            malicious=True,
            expected_rules={"TITAN-011"},
        )
    )

    # TITAN-012: a documented OneNote FileDataStoreObject carries a PE-like
    # payload and a URL.
    samples.append(
        Sample(
            "mal_onenote_executable_delivery",
            _onenote_section([b"MZ retrieve https://stage.one-evil.example/payload"]),
            malicious=True,
            expected_rules={"TITAN-012"},
        )
    )

    # --- Malicious variants (second example per rule) -----------------------
    # These differ from the first example above so per-rule recall is measured on
    # more than one positive — a rule that only matched its exact design sample
    # would show up as a miss here.

    # TITAN-001 v2: 3 nested layers around a different (non-URL) marker.
    samples.append(
        Sample(
            "mal_deep_base64_v2",
            _nested_base64(b"stage0 loader marker alpha bravo charlie delta echo", 3),
            malicious=True,
            expected_rules={"TITAN-001"},
        )
    )

    # TITAN-002 v2: macro doc whose network IOC is a bare domain (not a URL), in
    # a different stream path with a different auto-exec trigger. (Note: RFC-5737
    # documentation IP ranges classify as non-public, so a doc-range IP would not
    # register as a network IOC — a domain keeps this deterministic and realistic.)
    vba2 = (
        b'Attribute VB_Name = "ThisDocument"\r\n'
        b"Sub Document_Open()\r\n"
        b'  MsgBox "resolve c2.evil.example then stage payload"\r\n'
        b"End Sub\r\n"
    )
    samples.append(
        Sample(
            "mal_office_macro_v2",
            build_cfb([("Macros/VBA/ThisDocument", vba2)]),
            malicious=True,
            expected_rules={"TITAN-002"},
        )
    )

    # TITAN-003 v2: different LOLBins (regsvr32 / cscript), no network IOC.
    samples.append(
        Sample(
            "mal_lolbin_regsvr32",
            b"regsvr32 /s /n /u /i:file.sct scrobj.dll & cscript //nologo run.vbs",
            malicious=True,
            expected_rules={"TITAN-003"},
        )
    )

    # TITAN-004 v2: high-entropy packed blob (seeded for determinism).
    samples.append(
        Sample(
            "mal_packed_v2",
            random.Random(0xC0FFEE).randbytes(4096),
            malicious=True,
            expected_rules={"TITAN-004"},
        )
    )

    # TITAN-005 v2: 3+ IOC types via URL + public IP + email (no domain).
    samples.append(
        Sample(
            "mal_multistage_v2",
            (
                b"loader http://malware.example/stage1\n"
                b"drop 203.0.113.200\n"
                b"exfil operator@evil.example\n"
            ),
            malicious=True,
            expected_rules={"TITAN-005"},
        )
    )

    # TITAN-006 v2: XOR-obfuscated C2 with a different single-byte key.
    plain2 = b"settings beacon=http://malware.example/xor2/gate stage config blob"
    samples.append(
        Sample(
            "mal_xor_c2_v2",
            bytes(b ^ 0x3C for b in plain2),
            malicious=True,
            expected_rules={"TITAN-006"},
        )
    )

    # TITAN-007 v2: PDF carrying an embedded ELF (not PE) via a stream.
    elf_payload = b"\x7fELF\x02\x01\x01" + b"\x00" * 200 + b"embedded elf loader"
    pdf2 = build_pdf(
        [
            (1, b"<< /Type /Catalog /OpenAction 3 0 R >>"),
            (3, b"<< /S /JavaScript /JS 5 0 R >>"),
            (5, flate_stream(b"", elf_payload)),
        ]
    )
    samples.append(
        Sample(
            "mal_pdf_elf",
            pdf2,
            malicious=True,
            expected_rules={"TITAN-007"},
        )
    )

    # TITAN-008 v2: a ZIP signature appended to another valid PNG.
    samples.append(
        Sample(
            "mal_hidden_media_zip",
            _png_with_appended(b"PK\x03\x04 hidden archive payload"),
            malicious=True,
            expected_rules={"TITAN-008"},
        )
    )

    # TITAN-009 v2: an auto-linked/update-requested RTF OLE object. Automatic
    # behavior is sufficient even without a network IOC in the synthetic bytes.
    samples.append(
        Sample(
            "mal_rtf_autolink_object",
            _rtf_object(
                b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1 bounded OLE payload",
                b"\\objautlink\\objupdate",
            ),
            malicious=True,
            expected_rules={"TITAN-009"},
        )
    )

    # TITAN-010 v2: native-call dispatch from a macro sheet.
    samples.append(
        Sample(
            "mal_xlm_call",
            _xlm_workbook('=CALL("kernel32","WinExec","JCJ","calc.exe",1)'),
            malicious=True,
            expected_rules={"TITAN-010"},
        )
    )

    # TITAN-011 v2: a different package exposes its infrastructure only in the
    # executable stream, exercising recursive IOC collection.
    samples.append(
        Sample(
            "mal_msi_executable_delivery_v2",
            _msi_package(
                ["Updater", "InstallFiles"],
                b"MZ contact second-stage.msi-evil.example for configuration",
            ),
            malicious=True,
            expected_rules={"TITAN-011"},
        )
    )

    # TITAN-012 v2: the network indicator is a bare domain inside a second
    # synthetic executable object.
    samples.append(
        Sample(
            "mal_onenote_executable_delivery_v2",
            _onenote_section(
                [b"MZ contact second-stage.one-evil.example for configuration"]
            ),
            malicious=True,
            expected_rules={"TITAN-012"},
        )
    )

    # --- Benign samples -----------------------------------------------------

    samples.append(
        Sample(
            "ben_readme",
            b"# Project README\n\nThis is a normal text document describing usage.\n"
            b"Run the tool with --help for options. Nothing suspicious here.\n" * 3,
            malicious=False,
        )
    )

    samples.append(
        Sample(
            "ben_json_config",
            b'{\n  "name": "widget",\n  "version": "1.2.3",\n'
            b'  "settings": {"timeout": 30, "retries": 3}\n}\n',
            malicious=False,
        )
    )

    # Single-layer base64 of ordinary text (not nested — must not trip 001).
    samples.append(
        Sample(
            "ben_single_base64",
            base64.b64encode(b"The quarterly report is attached for your review."),
            malicious=False,
        )
    )

    # A clean PDF with a text stream, no JS / no embedded PE.
    clean_pdf = build_pdf(
        [
            (1, b"<< /Type /Catalog /Pages 2 0 R >>"),
            (2, b"<< /Type /Pages /Kids [] /Count 0 >>"),
            (4, flate_stream(b"", b"BT /F1 12 Tf (Hello, world.) Tj ET")),
        ]
    )
    samples.append(Sample("ben_clean_pdf", clean_pdf, malicious=False))

    # A benign CFB doc (e.g. a plain document stream, no network IOCs).
    samples.append(
        Sample(
            "ben_clean_doc",
            build_cfb(
                [("WordDocument", b"Meeting notes: agenda, action items, none.")]
            ),
            malicious=False,
        )
    )

    # Ordinary gzip of a log file (compresses, but nothing malicious).
    samples.append(
        Sample(
            "ben_gzip_log",
            zlib.compress(b"INFO service started\nINFO request handled ok\n" * 20),
            malicious=False,
        )
    )

    samples.append(
        Sample(
            "ben_source_code",
            b"import os\n\ndef main():\n    print('hello world')\n\n"
            b"if __name__ == '__main__':\n    main()\n",
            malicious=False,
        )
    )

    # --- Adversarial-but-benign near-misses ---------------------------------
    # These deliberately sit close to a rule's trigger without crossing it, to
    # stress precision (a rule that fires here is a false positive).

    # A single URL only — one IOC type, must NOT trip multi-stage (needs 3+).
    samples.append(
        Sample(
            "ben_single_url",
            b"See our documentation at https://docs.example.com/getting-started for setup.",
            malicious=False,
        )
    )

    # A legitimate PDF that contains JavaScript but NO embedded executable —
    # must NOT trip the malicious-PDF rule (which requires a PE/ELF signature).
    js_pdf = build_pdf(
        [
            (1, b"<< /Type /Catalog /OpenAction 3 0 R >>"),
            (3, b"<< /S /JavaScript /JS 5 0 R >>"),
            (
                5,
                flate_stream(
                    b"", b"app.alert('Please enable content'); // benign form script"
                ),
            ),
        ]
    )
    samples.append(Sample("ben_pdf_js_only", js_pdf, malicious=False))

    # A valid image without trailing or framed hidden content must not trip
    # the hidden-media rule.
    samples.append(Sample("ben_clean_png", _png_with_appended(), malicious=False))

    # A normal RTF hyperlink without an embedded object is not active content.
    samples.append(
        Sample(
            "ben_rtf_hyperlink",
            b"{\\rtf1\\ansi Visit https://docs.example.com/rtf for help.}",
            malicious=False,
        )
    )

    # A passive non-executable object with no network or auto-update behavior
    # is a precision near-miss for TITAN-009.
    samples.append(
        Sample(
            "ben_rtf_passive_attachment",
            _rtf_object(b"Quarterly report attachment"),
            malicious=False,
        )
    )

    # A macro sheet with an ordinary arithmetic function remains visible but
    # does not meet the high-risk execution rule.
    samples.append(
        Sample(
            "ben_xlm_ordinary_formula",
            _xlm_workbook("=SUM(1,2)"),
            malicious=False,
        )
    )

    # A suspicious-looking formula in a normal worksheet is not an XLM macro
    # sheet and must not be promoted into the XLM artifact path.
    samples.append(
        Sample(
            "ben_worksheet_exec_text",
            _xlm_workbook('=EXEC("documented function")', macro_sheet=False),
            malicious=False,
        )
    )

    # An ordinary MSI with a product support URL but no embedded executable is
    # a precision near-miss for TITAN-011.
    samples.append(
        Sample(
            "ben_msi_support_url",
            _msi_package(["Example Product", "https://support.example.com/msi"]),
            malicious=False,
        )
    )

    # An offline MSI carrying an executable custom-action blob lacks network
    # infrastructure and therefore remains below the correlation threshold.
    samples.append(
        Sample(
            "ben_msi_offline_executable",
            _msi_package(["Offline Tool", "InstallFiles"], b"MZ synthetic helper"),
            malicious=False,
        )
    )

    # A valid empty OneNote section is a format-recognition near-miss.
    samples.append(Sample("ben_onenote_empty", _onenote_section([]), malicious=False))

    # A passive PDF attachment may include a normal URL but is not executable
    # delivery and must not trip TITAN-012.
    samples.append(
        Sample(
            "ben_onenote_pdf_attachment",
            _onenote_section([b"%PDF-1.7 https://docs.example.com/guide"]),
            malicious=False,
        )
    )

    # Deeply *nested directories* description, but only a single base64 layer —
    # must NOT trip deep-base64 nesting.
    samples.append(
        Sample(
            "ben_single_base64_long",
            base64.b64encode(
                b"Release notes: many nested modules and layers of configuration, all benign."
            ),
            malicious=False,
        )
    )

    # A config file that mentions two domains only (2 IOC types < 3 threshold).
    samples.append(
        Sample(
            "ben_two_domains",
            b"# hosts\nprimary = cdn.example.com\nmirror = mirror.example.net\n",
            malicious=False,
        )
    )

    # A benign shell script that runs ordinary commands (no LOLBin tokens).
    samples.append(
        Sample(
            "ben_shell_script",
            b"#!/bin/sh\nset -e\ncp build/app /usr/local/bin/app\necho 'installed'\n",
            malicious=False,
        )
    )

    # Documentation that *mentions* LOLBins by name without any abuse context.
    # Before the LOLBin rule required execution context, this bare mention would
    # false-positive on TITAN-003; it must now stay clean.
    samples.append(
        Sample(
            "ben_tool_mention",
            b"Troubleshooting guide: on Windows, open PowerShell or cmd.exe and run\n"
            b"the installer. PowerShell 5.1+ is required; wscript is not used.\n",
            malicious=False,
        )
    )

    return samples
