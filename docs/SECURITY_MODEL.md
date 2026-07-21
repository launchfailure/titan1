# Security Model

Titan is designed to process hostile or malformed inputs, but it is not a sandbox. The Python process, installed plugins, optional native libraries, and host filesystem remain part of the trusted computing base.

## Threat model

Inputs may attempt decompression bombs, parser confusion, deep recursion, node fan-out, pathological regular expressions, memory exhaustion, terminal/log injection, graph-syntax injection, or malicious archive paths.

## Defenses

- recursion, node-count, size, memory, and timeout limits;
- bounded decompression and archive extraction;
- content-hash deduplication;
- deterministic decoder and analyzer ordering;
- malformed-input recovery;
- explicit offline mode and opt-in enrichment;
- output escaping for HTML, DOT, Mermaid, and logs;
- strict-mode contract validation;
- out-of-process manifest plugins with timeout, output, memory, offline-network,
  and configuration-disclosure controls;
- hash-addressed quarantine with verified copy and restore;
- hash-bound assurance provider attestations;
- red-team, resource-bound, fuzz-invariant, and regression tests.

## Trust boundaries

Legacy plugins, plugin validation, rule packs, and optional native libraries can
still execute or influence in-process behavior and must be reviewed. Manifest
plugin isolation is crash/resource containment, not a complete OS sandbox: a
determined malicious extension may bypass Python-level permission guards.
Optional enrichment and assurance providers are outside the deterministic core.
The report, sample, and quarantine vaults contain sensitive material and should
be protected with operating-system access controls.

## Operational guidance

Run unknown samples in an isolated environment with least privilege. Do not mount sensitive directories unnecessarily. Keep real evidence out of public repositories and issue trackers. Preserve original evidence separately; Titan output is derived analysis, not a replacement for evidence handling procedures.

Deep Scan is static analysis, not antivirus real-time protection. Quarantine is
off by default, copies rather than moves by default, and never turns an
`INDETERMINATE` or `NO_MALICIOUS_EVIDENCE` result into a claim of safety.
