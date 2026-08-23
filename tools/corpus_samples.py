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
import os
import random
import struct
import sys
import zlib
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
    # Benign cases intentionally placed close to one or more rule boundaries.
    # Tracking these labels separately proves that every built-in rule has
    # adversarial negative coverage instead of receiving credit only from
    # unrelated clean files.
    near_miss_rules: Set[str] = field(default_factory=set)


def _nested_base64(payload: bytes, layers: int) -> bytes:
    out = payload
    for _ in range(layers):
        out = base64.b64encode(out)
    return out


def _png_chunk(kind: bytes, payload: bytes) -> bytes:
    body = kind + payload
    return (
        len(payload).to_bytes(4, "big")
        + body
        + (zlib.crc32(body) & 0xFFFFFFFF).to_bytes(4, "big")
    )


def _png(width: int, height: int, pixels: bytes) -> bytes:
    """Build a deterministic RGB PNG for media-rule calibration."""
    if len(pixels) != width * height * 3:
        raise ValueError("RGB pixel buffer does not match PNG dimensions")
    rows = b"".join(
        b"\x00" + pixels[row * width * 3 : (row + 1) * width * 3]
        for row in range(height)
    )
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + _png_chunk(b"IHDR", ihdr)
        + _png_chunk(b"IDAT", zlib.compress(rows))
        + _png_chunk(b"IEND", b"")
    )


def _lsb_carrier(payload: bytes, carrier_size: int) -> bytes:
    """Encode Titan's explicit test frame into bounded pixel LSBs."""
    framed = b"TITANSTEG\x00" + len(payload).to_bytes(4, "big") + payload
    bits = [(value >> shift) & 1 for value in framed for shift in range(7, -1, -1)]
    if len(bits) > carrier_size:
        raise ValueError("payload does not fit in synthetic LSB carrier")
    return bytes(
        0x80 | (bits[index] if index < len(bits) else 0)
        for index in range(carrier_size)
    )


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

    # TITAN-004: opaque executable payload — executable magic plus high entropy
    # and few decodes. Seeded (not os.urandom) so the evaluation is
    # deterministic and the committed metrics are reproducible.
    samples.append(
        Sample(
            "mal_packed",
            b"MZ" + random.Random(0x5EED).randbytes(4096),
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

    # TITAN-004 v2: high-entropy ELF-like payload (seeded for determinism).
    samples.append(
        Sample(
            "mal_packed_v2",
            b"\x7fELF\x02\x01\x01" + random.Random(0xC0FFEE).randbytes(4096),
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

    # TITAN-008: executable bytes appended beyond a valid PNG terminator.
    hidden_executable = b"MZ" + b"synthetic hidden executable marker"
    samples.append(
        Sample(
            "mal_png_appended_payload",
            _png(1, 1, b"\x80\x80\x80") + hidden_executable,
            malicious=True,
            expected_rules={"TITAN-008"},
        )
    )

    # TITAN-008 v2: framed C2 content hidden in image least-significant bits.
    hidden_c2 = b"https://hidden-c2.example/payload"
    samples.append(
        Sample(
            "mal_png_lsb_payload",
            _png(32, 16, _lsb_carrier(hidden_c2, 32 * 16 * 3)),
            malicious=True,
            expected_rules={"TITAN-008"},
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
            near_miss_rules={"TITAN-001"},
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
            near_miss_rules={"TITAN-002"},
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
            near_miss_rules={"TITAN-005", "TITAN-006"},
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
    samples.append(
        Sample(
            "ben_pdf_js_only",
            js_pdf,
            malicious=False,
            near_miss_rules={"TITAN-007"},
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
            near_miss_rules={"TITAN-001"},
        )
    )

    # A config file that mentions two domains only (2 IOC types < 3 threshold).
    samples.append(
        Sample(
            "ben_two_domains",
            b"# hosts\nprimary = cdn.example.com\nmirror = mirror.example.net\n",
            malicious=False,
            near_miss_rules={"TITAN-005"},
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
            near_miss_rules={"TITAN-003"},
        )
    )

    # Routine administration flags are not sufficient abuse evidence.
    samples.append(
        Sample(
            "ben_powershell_maintenance",
            b"powershell.exe -NoProfile -File C:\\Admin\\Rotate-Logs.ps1",
            malicious=False,
            near_miss_rules={"TITAN-003"},
        )
    )
    samples.append(
        Sample(
            "ben_cmd_batch",
            b"cmd.exe /c echo nightly backup completed successfully",
            malicious=False,
            near_miss_rules={"TITAN-003"},
        )
    )

    # Ordinary encrypted or incompressible data is high entropy but has no
    # executable/packer context. It must remain a generic entropy signal, not a
    # TITAN-004 detection.
    samples.append(
        Sample(
            "ben_encrypted_backup",
            random.Random(0xBACC).randbytes(4096),
            malicious=False,
            near_miss_rules={"TITAN-004"},
        )
    )
    samples.append(
        Sample(
            "ben_encrypted_message",
            random.Random(0xA35).randbytes(2048),
            malicious=False,
            near_miss_rules={"TITAN-004"},
        )
    )

    # Macro-capable container without network content, and network text with no
    # Office container, exercise both halves of TITAN-002 independently.
    benign_vba = (
        b'Attribute VB_Name = "Module1"\r\n'
        b'Sub AutoOpen()\r\n  MsgBox "Quarterly report ready"\r\nEnd Sub\r\n'
    )
    samples.append(
        Sample(
            "ben_macro_without_network",
            build_cfb([("Macros/VBA/Module1", benign_vba)]),
            malicious=False,
            near_miss_rules={"TITAN-002"},
        )
    )

    # Two observable categories are below TITAN-005's three-category threshold.
    samples.append(
        Sample(
            "ben_two_ioc_types",
            b"mirror updates.example.com\ncontact admin@example.com\n",
            malicious=False,
            near_miss_rules={"TITAN-005"},
        )
    )

    # XOR transformation without any recovered network observable must not be
    # promoted to the C2-specific TITAN-006 rule.
    benign_xor = b"local preference theme=dark retries=3 no remote endpoint"
    samples.append(
        Sample(
            "ben_xor_without_network",
            bytes(value ^ 0x5A for value in benign_xor),
            malicious=False,
            near_miss_rules={"TITAN-006"},
        )
    )

    # Executable magic outside a PDF is not evidence for TITAN-007.
    samples.append(
        Sample(
            "ben_executable_not_pdf",
            b"MZ" + b"\x00" * 256 + b"signed internal utility fixture",
            malicious=False,
            near_miss_rules={"TITAN-007"},
        )
    )

    # Clean and unframed images exercise the hidden-media boundary. Random LSBs
    # do not become evidence unless Titan's explicit frame or a recognized
    # embedded payload is recovered.
    samples.append(
        Sample(
            "ben_clean_png",
            _png(2, 2, b"\x80" * 12),
            malicious=False,
            near_miss_rules={"TITAN-008"},
        )
    )
    random_pixels = random.Random(0x1A6E).randbytes(16 * 16 * 3)
    samples.append(
        Sample(
            "ben_png_unframed_lsb_noise",
            _png(16, 16, random_pixels),
            malicious=False,
            near_miss_rules={"TITAN-008"},
        )
    )

    return samples
