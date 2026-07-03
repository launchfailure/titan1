# Threat Model

Titan analyzes **hostile, attacker-controlled input**. That is the whole job:
the bytes it decodes are malware, and a naive analyzer is itself an attack
surface. This document states the attacker we defend against, the assets we
protect, the guarantees we make, and the adversarial test suite that proves
them.

Almost no tool in this space states this honestly. This is our attempt to.

## Stated attacker

A capable adversary who fully controls the **input payload** and, in the
extended model, a **rule pack** loaded by the operator. The attacker's goal is
to turn the act of analysis against the operator:

- **A1 — Resource exhaustion (DoS):** craft input that makes Titan consume
  unbounded CPU, memory, disk, or wall-clock time (decompression bombs, node
  fan-out, quadratic algorithms, regex backtracking, infinite structural
  cycles).
- **A2 — Crash / uncaught exception:** malformed structure that makes a
  decoder/analyzer raise, aborting analysis or corrupting the report.
- **A3 — Output poisoning:** input that fabricates false artifacts or IOCs, or
  that makes one decoder mis-fire and suppress the correct decode chain.
- **A4 — Egress / SSRF:** input that induces the tool to make a network request
  the operator did not intend.
- **A5 — Report integrity:** input that produces a non-deterministic or
  schema-violating report, so downstream tooling cannot trust it.

Out of scope: an attacker who controls the **host** or the **engine source**
(that is the supply-chain concern — see [SUPPLY_CHAIN.md](SUPPLY_CHAIN.md)), and
side channels (timing/cache).

## Assets

- Operator CPU / memory / time (availability).
- The correctness and determinism of the emitted report (integrity).
- The operator's network boundary (confidentiality — no unintended egress).

## Guarantees

For any input, within the configured limits, Titan guarantees:

- **G1 (bounded output):** decompression/extraction output never exceeds the
  configured cap (`max_data_size`); a bomb is declined, not expanded.
- **G2 (bounded node count):** the analysis tree never exceeds
  `max_node_count`, **including the decoded-content path** that bypasses
  score-based pruning.
- **G3 (bounded time):** analysis terminates within the wall-clock deadline;
  every decoder/analyzer terminates quickly per call; no structural parser
  loops forever on a cyclic structure.
- **G4 (never crashes analysis):** a decoder/analyzer never raises uncaught;
  failure is signaled by the `(data, False)` / empty-list contract.
- **G5 (no unintended egress):** with `--offline` (or absent explicit
  enrichment opt-in), no network request is made; the guard is enforced, not
  just documented.
- **G6 (deterministic, valid reports):** same input + same version ⇒ a
  byte-identical normalized report that validates against the frozen schema.
- **G7 (bounded rule-pack regex):** a catastrophic-backtracking pack pattern is
  bounded by a hard timeout (or run under linear-time RE2).

## Guarantee → defense → test map

| Attacker | Guarantee | Defense | Proof |
|----------|-----------|---------|-------|
| A1 bombs | G1 | `_bounded_decompress` output cap; PDF/OLE caps | `test_decompression_bomb.py`, `test_resource_bounds.py` |
| A1 fan-out | G2 | hard node cap enforced on the decoded-content path | `test_engine_node_cap.py`, `test_resource_bounds.py` |
| A1 quadratic | G3 | incremental pre-scans; sampled XOR scoring | `test_analyzer_prescan.py`, `test_decoder_dos.py` |
| A1 cycles | G3 | FAT/mini-FAT/dir cycle guards (CFB), ref-cycle guard (PDF) | `test_cfb_parser.py`, `test_pdf_object_graph.py` |
| A2 crashes | G4 | defensive parsers; fuzz invariants | `test_fuzz_invariants.py`, `fuzz/` |
| A3 poisoning | G3/A3 | structural parsing (no window carving); scored decodes | `test_cfb_parser.py`, `test_xor_singlebyte.py` |
| A4 egress | G5 | `offline_guard.block_network` | `test_offline_guard.py`, `test_cli_offline_mode.py` |
| A5 integrity | G6 | determinism + schema contract | `test_golden_corpus.py`, `test_schema_contract.py` |
| A1 ReDoS | G7 | subprocess/RE2 hard timeout | `test_rule_pack_redos.py` |

## Red-team suite

[`tests/test_red_team.py`](../tests/test_red_team.py) is an adversarial suite
organized by the attacker actions above. Each test constructs a payload a real
attacker would use and asserts the corresponding guarantee holds. It is the
executable form of this document — if a guarantee regresses, a red-team test
fails.

## Residual risk

- Wall-clock bounds depend on the OS scheduler; a heavily oversubscribed host
  can exceed the nominal deadline (the bound is enforced cooperatively at node
  boundaries, plus per-decode SIGALRM where available).
- Detection quality is measured on a small synthetic corpus
  ([DETECTION_QUALITY.md](DETECTION_QUALITY.md)); field precision/recall will
  differ.
- The rule-pack subprocess timeout has process-spawn overhead; RE2 is preferred
  where available.
