# Decoder and Analyzer Calibration

Titan includes a labeled calibration runner for measuring transformation and
structured-parser quality independently of the threat-detection corpus.

## Metrics

Every case targets one named decoder or analyzer and declares whether it should
recognize and/or extract the input. Recognition answers whether the format or
transport boundary was identified; extraction answers whether usable output was
recovered. Positive decoder extraction cases can pin the exact output SHA-256,
and positive analyzer extraction cases can require specific artifact names.
The runner produces:

- true/false positives and true/false negatives;
- separate recognition and extraction metrics;
- precision, recall, F1, specificity, and accuracy per component;
- automatic parity against the live built-in decoder/analyzer registry;
- per-component case-class coverage for adversarial corpus requirements;
- case-level observations and errors;
- a configurable precision/recall quality gate.

The committed v1 corpus has 104 deterministic cases. It covers positive and
negative recognition for all 39 live built-in decoders and analyzers, plus one
malformed and one truncated case for each of the 13 structural analyzers.
Thirty-eight components also have positive extraction cases;
`OptionalArchive` currently has recognition coverage only because positive
extraction depends on separately installed format libraries. Brotli and
Zstandard extraction cases are committed and run when their optional Python
modules are installed; otherwise the report lists those extraction checks
under `dependency_skips` rather than claiming they ran. User-installed plugins
are reported when explicitly targeted but do not become obligations of Titan's
bundled built-in corpus.

## Run the gate

```bash
titan cli \
  --calibrate tests/fixtures/calibration/decoder-analyzer-v1.json \
  --calibration-out calibration.json
```

The command exits non-zero when any measured phase falls below
`calibration_min_precision` or `calibration_min_recall` (both default to 0.90),
when a live built-in lacks either a positive or targeted negative recognition
case, or when a required component lacks an adversarial case class.

## Corpus contract

The corpus uses schema version `1.0`. Each case contains `id`, `kind`
(`decoder` or `analyzer`), `component`, exactly one of `data_text`,
`data_base64`, `data_hex`, or a corpus-relative `fixture`, and at least one of
`expected_recognition` or `expected_match`. When `expected_recognition` is
omitted it defaults to `expected_match`. Omitting `expected_match` creates a
recognition-only case. Decoder positives may add `expected_output_sha256`;
analyzer positives may add `expected_artifacts`. Cases whose extraction needs
an optional package declare `required_modules`; recognition still runs when the
package is absent, while extraction is recorded as dependency-skipped.

Cases can declare `case_class` as `positive`, `clean_negative`, `malformed`,
`truncated`, `size_bound`, or `nested_chain`. When omitted, the runner infers
`positive` or `clean_negative` from the recognition label. A corpus-level
`required_case_classes` object maps `decoder` or `analyzer` to classes that
every live built-in of that kind must cover. Invalid labels and cases that fail
to load or evaluate cannot satisfy that coverage gate.

The bundled corpus sets `require_registry_parity` and requires analyzer
`malformed` and `truncated` classes, making both live-registry and structural
adversarial coverage part of the quality gate. Small ad-hoc corpora may omit
those fields when they are intentionally measuring only a subset.

```json
{
  "schema_version": "1.0",
  "cases": [
    {
      "id": "example",
      "kind": "decoder",
      "component": "ASCII85",
      "case_class": "positive",
      "data_text": "<~87cURD_*#1Blmd$+T~>",
      "expected_match": true,
      "expected_output_sha256": "76047422c639e6685da351084dd4ee7e509e4148d04cc157819aac5bcbe47b37"
    }
  ]
}
```

Every new heuristic decoder or structured analyzer should add at least one
positive case, a near-miss negative, malformed-input tests, and a resource-bound
regression. A perfect score on a small synthetic corpus is a regression signal,
not a field accuracy claim.
