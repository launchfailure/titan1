# Security Policy

## Supported Versions

This project is best-effort and maintained on a rolling basis. If you find a security issue, please report it; fixes are typically released in the next patch/minor release.

## Security model & hardening

Titan Decoder is designed to process **untrusted, potentially malicious input**
(samples, archives, logs). It runs entirely offline by default and parses
everything with best-effort, dependency-free code. The engine includes
defenses against common analysis-time abuse:

- **Decompression bombs**: Gzip/Bz2/LZMA/Zlib and PDF FlateDecode output is
  produced incrementally and capped at `max_data_size`, so a small input can't
  inflate into multi-GB memory use.
- **Algorithmic DoS**: the URL, HTML-entity, and OLE decoders were rewritten to
  avoid O(n^2) behavior; the OLE scan also caps matches per signature.
- **Resource limits**: recursion depth, node count, input size, per-operation
  timeouts, and optional memory caps bound every run.
- **Malformed-input tolerance**: corrupt SQLite browser histories, malformed
  CSV/JSONL rows, and non-object records are skipped rather than aborting the
  run; binary parsers (PE/ELF/TAR) fail closed on truncated/odd headers.
- **Offline-first**: `--offline` additionally enables a best-effort
  process-local network kill switch.

### Known trust boundary: rule-pack `content_regex`

Detection rule packs (`--rules-pack`) may contain `content_regex` patterns that
run with Python's `re` against content derived from the untrusted payload.
`re` has **no execution timeout** and its C match loop cannot be interrupted by
signals, so a catastrophic-backtracking pattern (e.g. `(a+)+$`) can hang a run
when the payload contains a triggering string. **Only load rule packs from
sources you trust**, and author patterns that avoid nested/ambiguous
quantifiers. This is a property of the stdlib regex engine, not a bug in Titan.

### Residual risk

These are mitigations, not guarantees. Always analyze unknown samples in a
disposable VM or otherwise isolated environment, as a non-root user, with
resource limits configured. See the Safety Recommendations in the README.

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security-sensitive reports.

Instead:

- Open a **private advisory** via GitHub Security Advisories (preferred), or
- Contact the maintainer via the email on the profile.

Include:

- A clear description of the issue and impact
- Minimal reproduction steps
- The smallest possible sample that reproduces the issue

### Important: Evidence / PII

Do not include real incident logs, browser history databases, or other sensitive evidence in security reports. If you must share artifacts, redact PII and provide synthetic/minimized samples.
