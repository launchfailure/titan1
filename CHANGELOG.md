# Changelog

## 2.0.2 — Engine reliability fixes (2026-07-02)

Reliability (engine no longer fails silently or nondeterministically):

- Fix silent no-op analysis off the main thread and on Windows: SIGALRM-based
  per-operation timeouts crashed where SIGALRM is unavailable, and the engine
  swallowed the per-decoder error — every decoder/analyzer was skipped with no
  warning. Timeouts now degrade to unguarded execution (the run-level
  wall-clock deadline and memory bounds still apply).
- Stop text-transform decoders (URL, HTML-entity, unicode-escape) from
  hijacking binary decode chains: decoding with `errors="ignore"` silently
  deleted non-UTF-8 bytes, reported the mangled output as a successful decode,
  and could outscore the correct decoder (e.g. Gzip), killing the chain and
  losing every IOC in ~6% of layered payloads. These decoders now require
  valid UTF-8 input.
- Reset smart-detection decoder state between `run_analysis()` calls, so
  results on a reused engine no longer depend on what was analyzed earlier.
- Register off-by-default decoders (uuencode/asn1/quoted-printable/base32)
  when enabled via config — previously the config flags had no effect.

Correctness:

- Validate the full RFC 1950 zlib header (CINFO, FCHECK) instead of one
  nibble, cutting false decode attempts on random binary data from ~6.5% to
  ~0.07%.
- Accept all valid unpadded base32 lengths (mod 8 in {0, 2, 4, 5, 7}).
- Fix the UU decoder's stripped-whitespace retry slicing one character too
  many (now matches CPython's reference formula).
- Label PE machine type 0x01C4 as ARM Thumb-2 (ARMNT), not ARM64.
- Restrict hex detection to strict hex digits (`int(x, 16)` also accepted
  `0x`/sign/underscore forms that `unhexlify` rejects).
- Align config decoder flags with the real decoder set (add
  `base64url`/`pem`/`utf16`; remove nonexistent `base85`) and fix
  `QuotedPrintableDecoder.can_decode` to return a bool.

Testing:

- 9 new regression tests covering each fix (199 total).
- Verified with 600 hard-mode stress iterations (100% IOC recovery, was ~94%)
  plus an adversarial harness: fuzzing, decompression bombs, nested-archive
  fan-out, flood inputs, and determinism checks — all bounded and crash-free.

## 2.0.1 — Hardening & correctness (2026-06-30)

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
