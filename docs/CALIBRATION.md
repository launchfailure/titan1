# Decoder and Analyzer Calibration

Titan includes a labeled calibration runner for measuring transformation and
structured-parser quality independently of the threat-detection corpus.

## Metrics

Every case targets one named decoder or analyzer and declares whether it should
match. Positive decoder cases can pin the exact output SHA-256; positive
analyzer cases can require specific artifact names. The runner produces:

- true/false positives and true/false negatives;
- precision, recall, F1, specificity, and accuracy;
- the same metrics per component;
- case-level observations and errors;
- a configurable precision/recall quality gate.

The committed v1 corpus has 27 positive/negative cases for ASCII85, raw
Deflate, PowerShell EncodedCommand, JavaScript escapes, Base58, Base91, RFC/MIME
email, scripts, Windows LNK, OOXML/XLM, RTF embedded-object extraction, MSI,
and OneNote embedded-file extraction.

## Run the gate

```bash
titan-decoder \
  --calibrate tests/fixtures/calibration/decoder-analyzer-v1.json \
  --calibration-out calibration.json
```

The command exits non-zero when any measured component falls below
`calibration_min_precision` or `calibration_min_recall` (both default to 0.90).

## Corpus contract

The corpus uses schema version `1.0`. Each case contains `id`, `kind`
(`decoder` or `analyzer`), `component`, exactly one of `data_text`,
`data_base64`, line-wrapped `data_base64_parts`, `data_hex`, or a
corpus-relative `fixture`, and
`expected_match`. Decoder positives may add `expected_output_sha256`; analyzer
positives may add `expected_artifacts`.

`data_base64_parts` is a non-empty array of strings joined before strict Base64
decoding. It is intended for large binary fixtures that need reviewable line
wrapping. When present it is authoritative; `data_text`, `data_hex`, and
`fixture` remain mutually exclusive with it.

```json
{
  "schema_version": "1.0",
  "cases": [
    {
      "id": "example",
      "kind": "decoder",
      "component": "ASCII85",
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
