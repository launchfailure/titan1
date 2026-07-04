#!/usr/bin/env python3
"""Golden-corpus tooling: deterministic inputs, report normalization, regen.

A golden corpus pins ``input -> expected normalized report`` fixtures so that
any change in *analysis output* (not just crashes) shows up as a reviewable
diff. Combined with the engine's determinism, this makes silent regressions in
analysis behavior impossible to merge.

``normalize_report`` strips the fields that legitimately vary run-to-run or
across the CI matrix (the random analysis id, wall-clock timestamps, duration,
tool/interpreter versions, platform) so the remaining structure — nodes, IOCs,
detections, provenance, manifest limits/components — is byte-comparable.

Usage:
    python tools/golden.py --regen      # regenerate tests/golden/expected/*
    python tools/golden.py --check      # verify current outputs match goldens
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import sys
from typing import Dict

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
sys.path.insert(0, os.path.join(_ROOT, "tests"))

from titan_decoder.core.engine import TitanEngine  # noqa: E402
from titan_decoder.config import Config  # noqa: E402

GOLDEN_DIR = os.path.join(_ROOT, "tests", "golden")
INPUT_DIR = os.path.join(GOLDEN_DIR, "inputs")
EXPECTED_DIR = os.path.join(GOLDEN_DIR, "expected")

# Fields removed before comparison because they legitimately vary run-to-run or
# across the test matrix. Everything else must be byte-stable.
_VOLATILE_META = ("analysis_id", "started_at", "finished_at", "duration_ms", "version")


def normalize_report(report: Dict) -> Dict:
    """Return a copy of ``report`` with run-to-run-variable fields removed."""
    r = copy.deepcopy(report)
    meta = r.get("meta")
    if isinstance(meta, dict):
        for k in _VOLATILE_META:
            meta.pop(k, None)
    rm = r.get("run_manifest")
    if isinstance(rm, dict):
        rm.pop("environment", None)  # python/platform vary across the matrix
        tool = rm.get("tool")
        if isinstance(tool, dict):
            tool.pop("version", None)
        # Plugin dirs are absolute home paths (e.g. /root vs /home/runner) that
        # differ across machines; drop them so the report is matrix-stable.
        components = rm.get("components")
        if isinstance(components, dict):
            plugins = components.get("plugins")
            if isinstance(plugins, dict):
                plugins.pop("plugin_dirs", None)
    return r


def normalized_json(report: Dict) -> str:
    return json.dumps(normalize_report(report), indent=2, sort_keys=True) + "\n"


def build_inputs() -> Dict[str, bytes]:
    """Deterministic golden inputs (no os.urandom — fixtures must be stable)."""
    import base64
    import gzip

    from _cfb_fixtures import build_cfb  # noqa: E402
    from _pdf_fixtures import build_pdf, flate_stream  # noqa: E402

    def prng(n: int, seed: int = 1234) -> bytes:
        # Simple deterministic byte stream (LCG); not for cryptography.
        out = bytearray()
        x = seed
        for _ in range(n):
            x = (1103515245 * x + 12345) & 0x7FFFFFFF
            out.append((x >> 16) & 0xFF)
        return bytes(out)

    inputs: Dict[str, bytes] = {}
    inputs["plain_iocs.txt"] = (
        b"contact http://example.com/a and 203.0.113.9 or admin@example.org\n"
    )
    inputs["nested_base64.txt"] = base64.b64encode(
        base64.b64encode(base64.b64encode(b"beacon http://c2.example/panel bytes here"))
    )
    inputs["xor_url.bin"] = bytes(
        b ^ 0x5A for b in b"config c2=http://malware.example/c2/panel endpoint"
    )
    # Deterministic gzip input across the whole Python matrix. mtime=0 zeroes
    # the timestamp; bytes 8 (XFL) and 9 (OS) of the gzip header otherwise vary
    # by Python build/platform, which would change the compressed root hash on
    # different runners. Both are informational and ignored by decoders, so
    # pinning them makes the input byte-reproducible everywhere.
    _gz = bytearray(gzip.compress(b"INFO log line ok\n" * 40, mtime=0))
    _gz[8] = 0x00  # XFL
    _gz[9] = 0xff  # OS = unknown (fixed)
    inputs["gzip_text.bin"] = bytes(_gz)
    inputs["cfb_macro.doc"] = build_cfb(
        [("Macros/VBA/Module1", b'Sub AutoOpen()\n url="http://evil.example/c2"\nEnd Sub\n')]
    )
    inputs["pdf_js.pdf"] = build_pdf(
        [
            (1, b"<< /Type /Catalog /OpenAction 3 0 R >>"),
            (3, b"<< /S /JavaScript /JS 5 0 R >>"),
            (5, flate_stream(b"", b"app.alert('http://evil.example/pdf');")),
        ]
    )
    inputs["multi_ioc.txt"] = (
        b"http://a.example/x\n203.0.113.5\nbad.example.net\nop@evil.example\n"
    )
    inputs["high_entropy.bin"] = prng(2048)
    return inputs


def _run(data: bytes) -> Dict:
    # Fresh engine + default config each time for reproducibility.
    return TitanEngine(Config()).run_analysis(data)


def regen() -> None:
    os.makedirs(INPUT_DIR, exist_ok=True)
    os.makedirs(EXPECTED_DIR, exist_ok=True)
    for name, data in build_inputs().items():
        with open(os.path.join(INPUT_DIR, name), "wb") as f:
            f.write(data)
        report = _run(data)
        with open(os.path.join(EXPECTED_DIR, name + ".json"), "w") as f:
            f.write(normalized_json(report))
    print(f"Regenerated {len(build_inputs())} golden fixtures in {EXPECTED_DIR}")


def check() -> int:
    failures = []
    for name, data in build_inputs().items():
        expected_path = os.path.join(EXPECTED_DIR, name + ".json")
        if not os.path.exists(expected_path):
            failures.append(f"{name}: missing golden (run --regen)")
            continue
        expected = open(expected_path).read()
        actual = normalized_json(_run(data))
        if actual != expected:
            failures.append(f"{name}: output differs from golden")
    if failures:
        for f in failures:
            print(f"MISMATCH: {f}", file=sys.stderr)
        return 1
    print(f"All {len(build_inputs())} golden fixtures match.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--regen", action="store_true", help="Regenerate goldens")
    parser.add_argument("--check", action="store_true", help="Check against goldens")
    args = parser.parse_args()
    if args.regen:
        regen()
        return 0
    return check()


if __name__ == "__main__":
    raise SystemExit(main())
