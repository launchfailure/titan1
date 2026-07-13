# Intelligence Contract and Calibration

This document defines Phase 1 of the Intelligence Layer roadmap.

## Contract

`IntelligenceEngine.analyze()` emits an object conforming to
`schemas/intelligence-report-v1.0.schema.json`.

Version `1.0` guarantees:

- required top-level fields remain present;
- scores stay within `0..100`;
- classifications and their score thresholds remain stable;
- signals retain `code`, `points`, and `summary`;
- ranked artifacts retain node identity, score, and reasons;
- output is deterministic for the same input report.

Adding optional fields is compatible only after the JSON Schema permits them.
Removing or renaming fields, changing types, changing thresholds, or changing
existing signal semantics requires a new contract version.

## Calibration corpus

`tests/fixtures/intelligence/calibration-v1.json` is the first deterministic
calibration corpus. Each case includes:

- a small normalized Titan report;
- the exact expected intelligence score;
- the expected classification;
- ordered signal codes;
- ordered top-artifact node IDs.

The corpus is deliberately synthetic and contains no live indicators or
incident data.

## Updating behavior safely

1. Add a focused corpus case that demonstrates the intended behavior.
2. Run the full test suite.
3. Review score changes across every existing calibration case.
4. Preserve existing results unless the behavior change is intentional.
5. For an incompatible change, add a new schema/corpus version instead of
   silently rewriting version `1.0`.

## Commands

```bash
python -m pytest tests/test_intelligence.py tests/test_intelligence_contract.py
python -m pytest
```

The schema validation test uses the existing development dependency
`jsonschema`. It skips cleanly when only the dependency-free runtime package is
installed.
