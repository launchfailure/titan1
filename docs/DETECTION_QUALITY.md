# Detection Quality

Titan's built-in detection rules and risk-score weights are measured against a
small, fully synthetic labeled corpus rather than asserted by hand. This page
documents the methodology, the current numbers, and how to reproduce them.

## Methodology

- **Corpus** — `tools/corpus_samples.py` generates a labeled set of
  documentation-range, synthetic samples: 7 "malicious" (each crafted to
  exercise one rule — deep base64 nesting, a CFB macro doc with a network IOC,
  a LOLBin command line, a high-entropy packed blob, multi-stage IOC
  infrastructure, an XOR-obfuscated C2 URL, and a PDF carrying an embedded PE)
  and 7 benign (a README, a JSON config, a single-layer base64 blob, a clean
  PDF, a clean CFB document, a gzipped log, and a source file). **No real
  malware is stored in the repository — only the generator (the harness).**
- **Harness** — `tools/eval_detections.py` runs the full engine plus the
  detection rules over every sample, compares the fired rule IDs against each
  sample's ground-truth labels, and reports per-rule precision/recall and the
  overall benign-vs-malicious risk-score separation.
- **Weights** — the 0–100 weights in `titan_decoder/core/risk_scoring.py` are
  tuned so the overall score separates the two classes. The docstring on
  `RiskScoringEngine` cites this measurement.

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

**Risk separation:** benign samples score at most **4**; every malicious sample
scores at least **15**. The classes do not overlap.

These numbers reflect a deliberately small, clean corpus and are a regression
anchor, not a claim of field accuracy. The value is the *method*: any rule or
weight change that regresses separation or a rule's precision is caught.

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
