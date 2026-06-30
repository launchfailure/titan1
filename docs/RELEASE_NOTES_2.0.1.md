# Titan Decoder v2.0.1 — Hardening & correctness

A patch release collecting post-2.0.0 security hardening and bug fixes.
No breaking changes and no new user-facing features.

> Maintainer: to publish, push the tag and draft a GitHub Release from it.
>
> ```bash
> git fetch origin
> git tag -a v2.0.1 -m "Titan Decoder v2.0.1 — hardening & correctness release" origin/main
> git push origin v2.0.1
> ```
>
> Then create the Release on GitHub using the tag `v2.0.1` and the notes below.

## Security / DoS resistance

- Bounded decompression for Gzip/Bz2/LZMA/Zlib and PDF FlateDecode
  (anti-decompression-bomb, capped by `max_data_size`).
- Bounded OLE decoder output and fixed an O(n^2) VBA-string scan; fixed O(n^2)
  blow-ups in the URL and HTML-entity decoders.
- Hardened evidence ingestion: O(n) indicator merge, bounded CSV field-size
  limit, and per-row skipping so a malformed row can't abort the whole run.
- Graceful handling of corrupt browser-history SQLite files.
- `psutil` is now truly optional — `--perf-profile` runs (timing + cProfile) and
  reports memory/CPU as `0.0` when psutil isn't installed, instead of crashing.
- Documented the rule-pack `content_regex` ReDoS trust boundary.

## Correctness

- ELF (64-bit / big-endian), PE (optional-header struct), and GNU-format tar
  parsing fixes.
- Reject invalid IPv4 addresses and correct public/private classification;
  hash-IOC exact-length matching; ROT13 false-IOC gate.
- UU decoder reimplemented without the deprecated stdlib `uu` module;
  UU/QuotedPrintable return-contract fix on the failure path.
- IOC export: STIX value quote-escaping, MISP duplicate-IP dedup, and
  timezone-aware timestamps.

## Docs / maintenance

- New `SECURITY.md` "Security model & hardening" section; README and CHANGELOG
  updates; fixed a broken README configuration block.
- Dead-code removal and unused-module cleanup; 124+ regression tests added
  across decoders, analyzers, evidence/endpoint parsers, IOC export,
  decompression-bomb defenses, and the profiler.

**Full Changelog**: https://github.com/pragmaconflux/titan1/compare/v2.0.0-beta.2...v2.0.1
