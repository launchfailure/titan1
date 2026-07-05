# Changelog

## Unreleased

Audit cleanup (post-roadmap):

- Tolerate trailing bytes after a complete gzip/bz2/zlib/xz stream: zero
  padding or appended data (both common in real-world samples and carved
  artifacts) previously made the *entire* decode fail, discarding fully
  decoded content and its IOCs. A truncated or invalid first stream still
  fails, a partial trailing member never leaks partial output, and the
  decompression-bomb output cap is unchanged.
- Make the PDF `LZWDecode` output cap a hard stop and bound it by the
  document's configured `max_output`: the previous `break` only exited the
  inner code loop, so a crafted stream could keep growing output past the cap.
- Remove dead pruning-policy config (`quality_decay_threshold`,
  `max_consecutive_low_scores`, `min_content_similarity`,
  `prune_empty_decodes`, `prune_identical_content`): the keys were stored and
  echoed into `run_manifest.effective_config` but no logic ever read them, so
  they promised tuning knobs that did nothing. Unknown keys in existing user
  configs are still accepted and simply ignored, as before.
- Remove an always-false prune check in the analyzer extraction path (decoded
  content is never score-pruned by definition) and other dead code
  (`PruningEngine.get_pruning_stats`, unused `ResourceManager` timeout
  attributes).
- Batch mode now warns that `--evidence-timeline-out` is ignored instead of
  ignoring it silently.

Decoder correctness (Milestone 1):

- Replace the OLE signature-window carver with a real Compound File Binary
  (CFB/OLE2) parser: it walks the header, FAT/DIFAT, directory tree, and
  mini-stream, enumerates streams by their real directory path (e.g.
  `Macros/VBA/Module1`), and decompresses VBA source from module streams via
  the MS-OVBA compressed-container format. Extracted artifacts are named after
  real stream paths and the old window-carving false positives (signature bytes
  in random data) are gone.
- Make the PDF decoder object-graph aware: it parses indirect objects,
  decompresses object streams (`/Type /ObjStm`) so their packed objects become
  visible, resolves indirect references, and applies `/Filter` chains
  (FlateDecode, ASCIIHexDecode, ASCII85Decode, LZWDecode, with predictors). It
  extracts `/JS`, `/OpenAction`, and `/EmbeddedFile` by reference rather than by
  regex — resolving a stream referenced only as `5 0 R` and recovering objects
  packed inside an object stream.
- Extend the XOR decoder to repeating keys (lengths 2–8) via per-column
  frequency analysis, with sampled scoring that raises the size cap to 1 MB
  while keeping cost bounded (single full decode only on acceptance) and an
  entropy gate that skips near-random input.

Detection quality (Milestone 1/4):

- Add `tools/eval_detections.py` measuring per-rule precision/recall over a
  synthetic labeled corpus (`tools/corpus_samples.py`); the risk-score weights
  in `risk_scoring.py` cite that measurement. Numbers committed in
  `docs/detection_metrics.json` and `docs/DETECTION_QUALITY.md`, with
  per-release history in `docs/detection_quality_history.jsonl`. Fixed
  TITAN-001 to catch collapsed `RecursiveBase64` nesting.

Structure & verification (Milestone 2):

- Decompose `cli.main()` from a ~900-line function into a thin dispatcher plus
  independently-testable stages (load_input, run_analysis, attach_evidence,
  run_detections, write_outputs, …); CLI behaviors are asserted at the stage
  level.
- Add a fuzz harness (`fuzz/`) over every decoder and analyzer enforcing the
  never-raise / bounded-output / bounded-time invariants, with a checked-in seed
  corpus, Hypothesis property tests, and a bounded CI job.
- Wire mypy (non-strict baseline with a ratchet list), a pytest-cov 70% floor,
  and Python 3.13 into CI.
- Defend the rule-pack ReDoS surface: pack `content_regex` patterns run under
  linear-time RE2 when available, else in a killable subprocess with a hard
  timeout — a catastrophic `(a+)+$` pattern is bounded instead of hanging.

Contract, reproducibility & performance (Milestone 3):

- Bump the report schema to 1.2 with first-class per-node provenance (origin,
  producing decoder/analyzer, parent hash, confidence, artifact name, reason).
  CI validates every emitted report against `docs/report.schema.json`, the
  schema and code version are locked in step, and a compatibility policy is
  documented (`docs/SCHEMA_COMPATIBILITY.md`).
- Add a golden differential corpus (`tools/golden.py`) so any change in analysis
  output surfaces as a reviewable diff, plus reproducibility assertions
  (byte-identical normalized reports across runs).
- Add a performance regression gate (`tools/bench.py`) against a committed
  baseline: node counts checked exactly, wall-clock hardware-normalized.

Beyond A+ (Milestone 4):

- Publish a threat model (`docs/THREAT_MODEL.md`) with an executable red-team
  suite and property tests over the safety-critical resource bounds.
- Add a versioned plugin API contract (`titan_decoder.plugins.api`,
  `docs/PLUGIN_API.md`) with load-time compatibility checking.
- Add supply-chain integrity: a deterministic CycloneDX SBOM, reproducible-build
  guidance, and a signing release workflow (`docs/SUPPLY_CHAIN.md`).

CLI:

- Restore Ctrl+C: a signal handler set a flag nothing ever read, so SIGINT
  could not stop a running analysis (and the `except KeyboardInterrupt`
  handlers were unreachable). Interrupts now abort with exit code 130.
- Fix batch mode printing literal `\n` instead of newlines.
- Batch mode now processes files in sorted (deterministic) order, reuses one
  engine across files, warns about single-file-only options it ignores, and
  propagates its exit code under `python -m` invocation.
- Fix `--perf-profile` always reporting 0 nodes processed / 0 throughput.
- Validate `--evidence` paths before the analysis runs instead of after.
- `--list-decoders --list-analyzers` together now lists both.

Correctness:

- Detections, risk scoring, enrichment, and IOC/case exports now extract IOCs
  from every node preview (matching the engine report) instead of only
  Text-classified nodes, which silently dropped C2 indicators embedded in
  binary content from all downstream tooling.
- Correlation no longer matches every run against itself (the current run was
  recorded before correlating), and a user-configured `correlation_db_path`
  no longer silently disables correlation (string path crashed on `.parent`).
  The correlation DB now enforces `UNIQUE(type, value)` and stops re-inserting
  duplicate indicator rows on every run.
- STIX/MISP exports label hashes by digest length (MD5/SHA-1/SHA-256/…)
  instead of exporting every hash as SHA-256.
- IMSI detection worked never: the IMEI and IMSI regexes were identical and
  IMSI candidates were then filtered against the IMEI list. IMEIs are now
  Luhn-validated; 15-digit non-Luhn numbers are reported as IMSI candidates.
- `top_links` ranked confidence lexicographically ("medium" > "high"); it now
  compares numerically.
- Fix the `<?xml` structure-scoring pattern (matched bare "xml" anywhere) and
  anchor the two-byte MZ/BZ magics to the start of data.
- Evidence event IDs are now unique and deterministic (monotonic counter);
  wall-clock IDs collided within a microsecond and differed across runs.
- Parse millisecond epoch timestamps in evidence logs (previously interpreted
  as seconds, producing year-56000 dates).
- Unicode-escape decoder handles surrogate pairs (`😀`); previously
  one astral escape made the entire decode fail.
- PDF stream extraction handles nested dictionaries (e.g. `/DecodeParms
  <<...>>`), which the old `<<([^>]*)>>` regex could never match.
- Stop IOC extraction from reporting dotted .NET/scripting member access in
  download-cradle payloads (e.g. `Net.WebClient`, `Net.HttpWebRequest`) as
  bogus domains. Their trailing labels are verified non-TLDs and added to a
  denylist, so real C2 domains are unaffected.

Removed:

- Parallel archive extraction. `tarfile` is not thread-safe (concurrent reads
  can silently corrupt extracted content), the in-memory source gains nothing
  from threads, and completion-order results made reports nondeterministic.
  The `enable_parallel_extraction`/`max_parallel_workers` config keys are
  gone; extraction is sequential and deterministic.
- Phantom VirusTotal integration: the API-key config and "virustotal" provider
  listing implied lookups that no code performed.
- Dead config flags that nothing read: `enable_entropy_analysis`,
  `enable_script_analysis`, `enable_shellcode_detection`,
  `enable_string_extraction`, `enable_xor_keyfinding`,
  `enable_polymorphic_detection`, `enable_yara_generation`,
  `enable_html_reports`, `enable_pii_redaction` (log redaction is controlled
  by `--no-redaction`), and `vault_prune_days` (use `--vault-prune-days`).

Behavior:

- WHOIS enrichment honors its cooldown by waiting between queries instead of
  permanently skipping every indicator after the first with
  `{"_rate_limited": true}`.
- `meta.enrichment_providers` now lists providers that actually initialized
  (library present, DB/rules loaded), not what the config requested.
- A malformed `~/.titan_decoder/config.json` now logs a warning instead of
  silently reverting every setting to defaults.

Packaging / CI:

- Project metadata migrated from `setup.py` to the `[project]` table in
  `pyproject.toml`; ruff lint added to CI.

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
