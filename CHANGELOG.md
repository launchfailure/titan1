# Changelog

## Unreleased — Hardening & correctness

Security / DoS resistance (untrusted-input hardening):

- Bound decompressor output for Gzip/Bz2/LZMA/Zlib to defeat decompression
  bombs (incremental, multi-stream-aware, capped by `max_data_size`).
- Bound PDF FlateDecode output the same way, so a malicious object stream
  can't exhaust memory.
- Bound OLE decoder output and fix an O(n^2) VBA-string scan that could hang
  on crafted documents (per-signature match cap + output budget).
- Fix O(n^2) blow-ups in the URL and HTML-entity decoders (single-pass
  rewrites) that let small inputs burn large amounts of CPU.
- Harden evidence ingestion: O(n) indicator merge (was O(n^2)), a bounded CSV
  field-size limit, and per-row skipping so a malformed row/field can't abort
  the whole run.
- Degrade gracefully on corrupt browser-history SQLite files instead of
  crashing the evidence run.
- Make `psutil` truly optional: `--perf-profile` now runs (timing + cProfile)
  and reports memory/CPU as `0.0` when psutil isn't installed, instead of
  crashing with `ModuleNotFoundError`.
- Document the rule-pack `content_regex` ReDoS trust boundary: patterns run
  with Python's `re` (no timeout); only load packs you trust.

Correctness:

- Fix ELF metadata parsing for 64-bit and big-endian binaries.
- Fix PE metadata parsing (broken optional-header struct format) and bound the
  image-base read.
- Detect GNU-format tar archives (`ustar` magic at offset 257).
- Reject invalid IPv4 addresses and correct public/private classification via
  `ipaddress`.
- Stop hex blobs being mis-reported as hash IOCs (exact-length matching).
- Stop ROT13 from mangling plaintext and polluting IOCs (English-likeness gate).
- Reduce IOC/forensics false positives from filenames and encoded layers.
- Reimplement the UU decoder without the deprecated stdlib `uu` module, and fix
  the UU/QuotedPrintable decoder return contract on the failure path.
- Fix IOC export: STIX value quote-escaping and MISP duplicate-IP dedup;
  timezone-aware timestamps.

Maintenance:

- Remove dead path-pruning code and unused `titan_decoder.core` modules.
- Add regression tests across decoders, analyzers, evidence/endpoint parsers,
  IOC export, decompression-bomb defenses, and the profiler (124+ tests).

## 2.0.0

- Evidence ingestion layer (canonical events/indicators) with pivots/last-seen.
- Evidence links (reason codes + confidence) and evidence timeline export.
- Endpoint artifact parsing: PowerShell history and browser history SQLite.
- Deterministic enrichment caching (SQLite) with refresh control.
- CLI hardening: offline-first mode, clean outputs, doctor mode, vault.
