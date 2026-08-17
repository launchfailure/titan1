# Malware configuration extractors

Titan's seed set demonstrates production-oriented API 1.2 extractors with
strict input bounds and format-specific validation. They execute in Titan's
isolated, offline plugin worker and contribute normalized results to
`report["config_extractions"]`.

## Seed families

| Family | Accepted representation | Maximum input | Required validation |
| --- | --- | ---: | --- |
| Cobalt Strike Beacon 3.x/4.x | Decoded or `0x69`/`0x2e` XOR-encoded 4 KiB settings block embedded in an artifact | 16 MiB | Beacon TLV prefix plus valid port, sleep interval, and C2 fields |
| Remcos | Decrypted settings envelope recovered from a resource or memory | 1 MiB | Exact settings delimiter, at least 15 fields, endpoint tuple, and stable boolean slots |

The Cobalt Strike extractor normalizes the endpoint, timing, jitter, user
agent, URI, pipe, watermark, and host-header fields when present. The Remcos
extractor normalizes its C2 endpoint, botnet/campaign, connection interval,
and mutex. Remcos resource discovery and RC4 decryption remain separate
forensic preprocessing steps; the extractor intentionally does not guess at
arbitrary PE resource blobs.

## Calibration and safety

Tests use byte fixtures that reproduce the families' real serialized layouts,
cover both supported Beacon XOR variants, and include truncated, marker-only,
invalid-timing, short-delimiter, and invalid-boolean near misses. Parsers cap
the bytes inspected, cap field counts, avoid network and filesystem I/O, and
return no partial attribution when required invariants fail.

The layouts were independently implemented from public technical references:

- CAPE Sandbox's `CobaltStrikeBeacon.py` configuration definitions.
- CAPE Sandbox's `Remcos.py` field layout, including research references to
  Cisco Talos and Elastic Security Labs in its source header.

These are seed implementations, not a claim of universal family/version
coverage. New variants should add a labeled positive/negative fixture before
loosening any invariant.
