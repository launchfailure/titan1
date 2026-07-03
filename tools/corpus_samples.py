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
import sys
import zlib
from dataclasses import dataclass, field
from typing import List, Set

# Reuse the synthetic CFB / PDF builders from the test fixtures. This harness is
# a developer tool (not shipped in the package), so importing test helpers is
# fine and keeps the builders DRY.
_TESTS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tests")
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

    # TITAN-004: encrypted/packed payload — high entropy, few decodes.
    samples.append(
        Sample(
            "mal_packed",
            os.urandom(2048),
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
    mz_payload = b"MZ\x90\x00" + b"\x00" * 200 + b"This program cannot be run in DOS mode"
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
            build_cfb([("WordDocument", b"Meeting notes: agenda, action items, none.")]),
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

    return samples
