# Detection Quality

Titan's built-in detection rules and risk-score weights are measured against a
small, fully synthetic labeled corpus rather than asserted by hand. This page
documents the methodology, the current numbers, and how to reproduce them.

## Methodology

- **Corpus** — `tools/corpus_samples.py` generates a labeled set of
  documentation-range, synthetic samples: **16 malicious** (two per rule, so
  per-rule recall is measured on more than one example — a rule that only
  matched its exact design sample would show up as a miss) covering deep base64
  nesting, CFB macro docs with a network IOC, LOLBin command lines, high-entropy
  executable-like blobs, multi-stage IOC infrastructure, XOR-obfuscated C2,
  PDFs carrying an embedded PE/ELF, and hidden PNG payloads; and **23 benign**,
  including at least **two labeled adversarial near-misses per rule**. These
  deliberately sit just under a trigger: single-layer Base64, clean/macro-only
  CFB, routine PowerShell and `cmd.exe` administration, generic ciphertext,
  one/two-category IOC documents, XOR without a network observable, JavaScript-
  only PDFs, non-PDF executables, and clean/unframed PNGs.
  The corpus is fully deterministic (seeded RNG, no `os.urandom`). **No real
  malware is stored in the repository — only the generator (the harness).**
- **Harness** — `tools/eval_detections.py` runs the full engine plus the
  detection rules over every sample, compares the fired rule IDs against each
  sample's ground-truth labels, and reports per-rule precision/recall and the
  overall benign-vs-malicious risk-score separation. The built-in rule list is
  discovered from the live engine rather than duplicated in the harness, so a
  newly added rule fails CI until it receives enough positive and targeted
  near-miss coverage.
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
| TITAN-008 | 1.000     | 1.000  | 1.000 |

Each rule now has **two** positive samples (recall is measured on more than one
example), and precision is checked against 23 benign samples. Every rule also
has at least **two explicitly labeled near-misses**, preventing unrelated clean
files from creating a misleading appearance of negative coverage. The LOLBin
rule (TITAN-003) now requires actual abuse evidence rather than routine
`-NoProfile`, `cmd.exe /c`, or `cscript //nologo` administration. TITAN-004
requires high entropy plus executable/packer context; generic encrypted bytes
remain visible through the separate entropy risk signal without becoming a
detection.

**Risk separation:** benign samples score at most **10**; every malicious sample
scores at least **15**. The classes do not overlap.

The CI quality gate requires, for every live built-in rule:

- precision and recall of at least 0.800;
- at least two labeled positive samples;
- at least two targeted benign near-misses;
- no targeted near-miss firing its associated rule; and
- complete benign/malicious risk-score separation.

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

`tests/test_detection_eval.py` runs the same evaluation in CI. The evaluator
also exits non-zero when any quality, coverage, label-integrity, or risk-
separation gate fails, so both direct script use and pytest enforce the same
contract.

## Extending the corpus

Add samples to `build_corpus()` in `tools/corpus_samples.py` with a `malicious`
flag and the set of `expected_rules`. Prefer synthetic, documentation-range
content. For a larger malicious set, generate or reference samples from
theZoo / MalwareBazaar **out of tree** and keep only the harness here.
