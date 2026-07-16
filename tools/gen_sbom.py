#!/usr/bin/env python3
"""Generate a CycloneDX SBOM for the Titan distribution.

For a forensic/IR tool the output may become evidence, so supply-chain
integrity of the tool itself is part of the product. This emits a minimal but
valid CycloneDX 1.5 SBOM describing the package and its declared dependencies.

Titan's runtime core is intentionally dependency-free, so the SBOM is small by
design; declared runtime extras are listed as optional components. The committed
SBOM (docs/sbom.cdx.json) is regenerated on release.

Usage:
    python tools/gen_sbom.py [--out docs/sbom.cdx.json]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from titan_decoder import __version__  # noqa: E402

# Optional dependencies (extras), declared for transparency. The runtime core
# has an empty install_requires; these are only needed for optional features.
OPTIONAL_DEPS = [
    ("psutil", ">=7.2.2"),
    ("geoip2", ">=5.2.0"),
    ("python-whois", ">=0.9.6"),
    ("yara-python", ">=4.5.4"),
    ("requests", ">=2.34.2"),
    ("PyYAML", ">=6.0.3"),
    ("textual", ">=0.89"),
]


def _purl(name: str, version: str) -> str:
    return f"pkg:pypi/{name}@{version}"


def _bom_ref(name: str) -> str:
    return f"component:{name}"


def build_sbom(deterministic: bool = True) -> dict:
    components = []
    for name, ver in OPTIONAL_DEPS:
        clean_ver = ver.lstrip(">=~ ") if ver[0] in "><=~ " else ver
        components.append(
            {
                "type": "library",
                "bom-ref": _bom_ref(name),
                "name": name,
                "version": clean_ver,
                "scope": "optional",
                "purl": _purl(name, clean_ver),
            }
        )

    metadata = {
        "component": {
            "type": "application",
            "bom-ref": _bom_ref("titan-decoder"),
            "name": "titan-decoder",
            "version": __version__,
            "description": "Advanced payload decoding and analysis engine",
            "licenses": [{"license": {"id": "AGPL-3.0-or-later"}}],
            "purl": _purl("titan-decoder", __version__),
        },
        "tools": [{"name": "gen_sbom.py", "vendor": "PragmaConflux"}],
    }
    # Deterministic builds: omit a wall-clock timestamp so the SBOM is
    # byte-reproducible for the same version. Reproducibility is a feature here.
    if not deterministic:
        import datetime

        metadata["timestamp"] = datetime.datetime.now(
            datetime.timezone.utc
        ).isoformat()

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": metadata,
        "components": components,
    }
    # Serial number derived deterministically from the version so re-runs match.
    digest = hashlib.sha256(f"titan-decoder@{__version__}".encode()).hexdigest()
    sbom["serialNumber"] = (
        f"urn:uuid:{digest[0:8]}-{digest[8:12]}-{digest[12:16]}-"
        f"{digest[16:20]}-{digest[20:32]}"
    )
    return sbom


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out",
        default=os.path.join(_ROOT, "docs", "sbom.cdx.json"),
        help="Output path (default: docs/sbom.cdx.json)",
    )
    parser.add_argument(
        "--with-timestamp",
        action="store_true",
        help="Include a wall-clock timestamp (breaks byte-reproducibility)",
    )
    args = parser.parse_args()
    sbom = build_sbom(deterministic=not args.with_timestamp)
    with open(args.out, "w") as f:
        json.dump(sbom, f, indent=2, sort_keys=True)
        f.write("\n")
    print(f"Wrote CycloneDX SBOM ({len(sbom['components'])} components) to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
