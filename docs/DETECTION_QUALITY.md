# Detection Quality

Titan's built-in detection rules and risk-score weights are measured against a
small, fully synthetic labeled corpus rather than asserted by hand. This page
documents the methodology, the current numbers, and how to reproduce them.

## Methodology

- **Corpus** — `tools/corpus_samples.py` generates a labeled set of
  documentation-range, synthetic samples: **14 malicious** (two per rule, so
  per-rule recall is measured on more than one example — a rule that only
  matched its exact design sample would show up as a miss) covering deep base64
  nesting, CFB macro docs with a network IOC, LOLBin command lines, high-entropy
  packed blobs, multi-stage IOC infrastructure, XOR-obfuscated C2, and PDFs
  carrying an embedded PE/ELF; and **13 benign**, including **adversarial
  near-misses** that deliberately sit just under a rule's trigger (a single-URL
  doc, a JS-only PDF with no embedded executable, a single-layer base64 blob, a
  two-domain config, a benign shell script, and a documentation snippet that
  *names* PowerShell/cmd.exe without any abuse context) to stress false-positive
  precision.
  The corpus is fully deterministic (seeded RNG, no `os.urandom`). **No real
  malware is stored in the repository — only the generator (the harness).**
- **Harness** — `tools/eval_detections.py` runs the full engine plus the
  detection rules over every sample, compares the fired rule IDs against each
  sample's ground-truth labels, and reports per-rule precision/recall and the
  overall benign-vs-malicious risk-score separation.
- **Weights** — the 0–100 weights in `titan_decoder/core/risk_scoring.py` are
  tuned so the overall score separates the two classes. The docstring on
  `RiskScoringEngine` cites this measurement. A **per-severity floor** also
  ensures a fired rule never reads below its own severity (a medium-severity
  rule floors the assessment to MEDIUM, high to HIGH, critical to CRITICAL), so
  a genuine detection can't be under-prioritized as LOW.

## Current results

Committed machine-readable numbers: [`detection_metrics.json`](detection_metrics.json).

| Rule      | Precision | Recall | F1    |
|-----------|-----------|--------|-------|
| TITAN-001 | 1.000     | 1.000  | 1.000 |
| TITAN-002 | 1.000     | 1.000  | 1.000 |
| TITAN-003 | 1.000     | 1.000  | 1.000 |
| TITAN-004 | 1.000     | 1.000  | 1.000 |
| TITAN-005 | 1.000     | 1.000  | 1.000 |
| TITAN-006 | 1.000     | 1.000  | 1.000 |
| TITAN-007 | 1.000     | 1.000  | 1.000 |

Each rule now has **two** positive samples (recall is measured on more than one
example), and precision is checked against 13 benign samples that include
adversarial near-misses. The LOLBin rule (TITAN-003) requires an actual
abuse/execution-context token, so a document that merely *names* PowerShell or
cmd.exe no longer false-positives.

**Risk separation:** benign samples score at most **7**; every malicious sample
scores at least **15**. The classes do not overlap.

These numbers reflect a deliberately small, clean corpus and are a regression
anchor, **not a claim of field accuracy** — 1.000/1.000 here means each rule
fires on its designed cases and none of the benign near-misses trip a rule, not
that the engine is 100% accurate on real-world malware. The value is the
*method*: any rule or weight change that regresses separation or a rule's
precision is caught in CI.

## Reproducing

```bash
python tools/eval_detections.py --json docs/detection_metrics.json
```

`tests/test_detection_eval.py` runs the same evaluation in CI and asserts that
the benign/malicious risk scores stay separated and that no rule's precision
regresses below 0.8, so the corpus stays honest as rules evolve.

## Extending the corpus

Add samples to `build_corpus()` in `tools/corpus_samples.py` with a `malicious`
flag and the set of `expected_rules`. Prefer synthetic, documentation-range
content. For a larger malicious set, generate or reference samples from
theZoo / MalwareBazaar **out of tree** and keep only the harness here.
