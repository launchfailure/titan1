# YARA Detection Quality

Titan measures the shipped starter YARA pack against a deterministic,
synthetic labeled corpus. The corpus contains two positive variants for every
rule plus benign near-misses that mention the same tools and strings without
the complete abuse chain. The current 32-case corpus measures nine starter
rules, including command-line and PowerShell scheduled-task persistence
variants plus task-query and routine-maintenance lookalikes.

The committed machine-readable result is
[`yara_detection_metrics.json`](yara_detection_metrics.json). It is a
regression anchor rather than a claim of field accuracy: synthetic precision
and recall must remain at or above 0.8 for every starter rule, and every rule
must retain at least two labeled positive samples.

Run the evaluation with:

```bash
python tools/eval_yara.py --json docs/yara_detection_metrics.json
```

`tests/test_yara_eval.py` enforces the same thresholds in CI. Additions to the
starter pack must update `tools/yara_corpus_samples.py` with positive variants
and adversarial benign near-misses.
