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
            (5, flate_stream(b"", b"app.alert('Please enable content'); // benign form script")),
        ]
    )
    samples.append(Sample("ben_pdf_js_only", js_pdf, malicious=False))

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

    return samples
