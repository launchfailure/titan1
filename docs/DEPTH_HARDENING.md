# Titan Depth-Hardening Program

Titan's major feature surface is intentionally paused while the shipped engine
is made deeper, more measurable, and harder to fool. New product modes and
headline subsystems can return later; bug fixes and security corrections remain
in scope throughout this program.

This program follows the project charter: offline first, decoder first,
evidence first, deterministic, bounded, transparent, and defensive.

## What "depth" means

Depth is not another feature name. It is stronger evidence that an existing
capability works across varied, malformed, adversarial, and operationally
realistic inputs.

1. **Detection content and calibration** — more native and YARA content, with
   measured positives, targeted benign near-misses, cross-rule interactions,
   and truthful precision/recall reporting.
2. **Corpus quality** — larger labeled corpora built from multiple generators,
   public-safe fixtures, format variants, and field-derived misses; synthetic
   design samples remain regression anchors, not field-accuracy claims.
3. **Decoder and parser correctness** — every advertised decoder/analyzer gets
   positive, clean-negative, malformed, truncated, oversized, recursive, and
   cross-format cases where applicable.
4. **Adversarial robustness** — fuzzing, decompression bombs, archive traversal,
   parser confusion, Unicode edge cases, plugin failures, report poisoning, and
   resource-exhaustion attempts fail closed.
5. **Determinism and provenance** — cross-platform golden reports, stable graph
   hashes, schema compatibility, canonical ordering, and parent/child evidence
   integrity are continuously verified.
6. **Code assurance** — raise the coverage floor in measured steps, remove mypy
   exemptions module by module, strengthen lint rules, and add property and
   mutation tests where ordinary examples are weak.
7. **Performance and resource bounds** — expand benchmark shapes and verify
   time, memory, node, output, queue, and concurrency limits without weakening
   forensic output.
8. **Operational security** — harden plugin isolation, service authentication,
   quarantine and restoration, WSL/native boundaries, update/release integrity,
   and safe handling of hostile filenames and evidence metadata.
9. **External trust** — complete the independent parser review, publish its
   scope and limitations, reproduce results on clean systems, and grow a real
   third-party corpus/plugin/user feedback loop.

## Ordered execution

### D1 — Detection-quality foundation

Current focused slice:

- derive the measured rule set from the live built-in registry;
- require every built-in rule to have multiple positives and targeted benign
  near-misses;
- include `TITAN-008` in published metrics;
- fail the evaluator on precision, recall, label, coverage, near-miss, or risk-
  separation regression;
- correct broad LOLBin and high-entropy false-positive boundaries.

Baseline gate: at least two positives and two targeted near-misses per built-in
rule. This is a floor, not the final content target.

### D2 — Detection-content scale

- Grow native and starter YARA content in small reviewed batches.
- Require each new rule to ship with multiple behavior variants, benign
  lookalikes, ATT&CK metadata, severity rationale, and graph-node coverage.
- Add multi-rule samples so interactions and risk stacking are measured.
- Expand toward hundreds of diverse labeled cases before making broad accuracy
  claims, then toward thousands using out-of-tree public or licensed corpora.
- Record misses and false positives by engine/rule version so content improves
  from evidence rather than count alone.

### D3 — Decoder/analyzer calibration parity

- Discover the live decoder/analyzer registry automatically, as D1 does for
  rules.
- Fail CI when an advertised component has no labeled calibration slice.
- Add positive, negative, malformed, truncation, size-bound, and nested-chain
  cases for every component.
- Separate format recognition accuracy from extraction correctness and output-
  hash determinism.

### D4 — Continuous adversarial testing

- Keep the bounded pull-request fuzz gate for fast feedback.
- Add longer scheduled fuzz campaigns with retained minimized reproducers.
- Cover analyzers, archives, evidence parsers, plugin transport, server request
  parsing, report loading, and export paths—not decoders alone.
- Track iterations, unique paths/cases, crashes, timeouts, and bound violations
  over time.

### D5 — Code-assurance ratchet

- Increase the coverage floor from 70% in reviewable steps without excluding
  difficult security-critical code.
- Remove one or a small related group of mypy exemptions per PR, starting with
  the core engine and evidence parsers.
- Expand lint rules only with a clean migration and a permanent CI gate.
- Add property tests for ordering, hashing, deduplication, bounds, and schema
  round trips.

### D6 — Determinism, provenance, and compatibility

- Verify golden reports on Linux and Windows across supported Python versions.
- Add property checks for root commitments, lineage hashes, graph ordering,
  deduplication, and stable export identities.
- Test old report/workspace/plugin contracts against current readers.
- Publish explicit compatibility and migration policy for every versioned
  schema.

### D7 — Performance and operational hardening

- Expand benchmarks beyond ten cases to deep graphs, large directories,
  archives, media, executables, evidence correlation, and concurrent service
  workloads.
- Measure peak memory and output amplification in addition to normalized time.
- Harden authentication, rate/queue bounds, artifact storage, cancellation,
  recovery, plugin containment, and quarantine atomicity.
- Exercise native Windows, WSL, Debian, and constrained-device workflows with
  repeatable smoke suites.

### D8 — Independent validation and trust

- Complete issue #145 with an assessor independent of implementation authors.
- Fix or explicitly risk-accept findings and publish scope limitations.
- Reproduce release artifacts, proof bundles, and test results from clean
  environments.
- Add signed releases and provenance attestations where the release workflow
  supports them.
- Treat external users, plugins, corpora, and reported misses as validation
  evidence; repository activity alone is not adoption proof.

## Pull-request rules during the depth phase

- One measurable hardening objective per focused branch.
- No direct changes to `main`; use a draft PR and require green CI.
- Every behavior change includes positive and adversarial negative tests.
- Generated metrics/proof files are refreshed in the same PR.
- Claims state corpus size and limitations; synthetic perfection is never
  presented as field accuracy.
- Major new modes, editions, or subsystems remain deferred until this document's
  measurement foundations and core assurance ratchets are established.

## Progress

| Slice | Status | Exit evidence |
|---|---|---|
| D1 detection-quality foundation | Complete | Live rule parity, `TITAN-008`, 2+ positives and 2+ targeted near-misses per rule, risk separation, and full CI |
| D2 detection-content scale | In progress | 48-case native and 32-case YARA corpora; scheduled-task batch adds two variants, three native near-misses, decoded-child coverage, and multi-rule interactions |
| D3 decoder/analyzer parity | In progress | 39/39 live built-ins have positive/negative recognition plus malformed/truncated coverage; size-bound and nested-chain depth continues |
| D4 continuous adversarial testing | Planned | Scheduled fuzzing with retained reproducers and broader harnesses |
| D5 code-assurance ratchet | Planned | Higher coverage floor and shrinking mypy exemption list |
| D6 determinism/provenance | Planned | Cross-platform golden and compatibility evidence |
| D7 performance/operations | Planned | Memory/amplification/concurrency and platform smoke gates |
| D8 independent validation | Blocked on external assessor | Published independent report and resolved findings |
