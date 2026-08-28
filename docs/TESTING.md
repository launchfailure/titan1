# Testing and CI

Titan's test strategy combines unit tests, contract tests, deterministic corpora, hostile-input tests, and end-to-end CLI coverage.

## Commands

```bash
python -m pip install -e '.[dev,workbench-ui,desktop-ui,formats]'
python -m pip install 'yara-python>=4.5.4'
python -m pytest --fail-on-skips
ruff check .
mypy titan_decoder
```

CI installs the Textual and desktop interfaces, optional format libraries,
JSON Schema validator, and YARA binding across the supported Python matrix.
`--fail-on-skips` makes those tests mandatory instead of silently reducing
coverage when an installation step regresses.

## Test categories

- decoder and analyzer behavior;
- engine recursion, scoring, pruning, and node caps;
- decompression and resource bounds;
- IOC and evidence parsing;
- detections and risk;
- Intelligence schema and calibration;
- Threat Intelligence catalog integrity and calibration;
- report and graph rendering;
- plugin behavior;
- packaging and supply-chain checks;
- fuzz invariants and red-team regressions.

## New graph tests

`tests/test_graph_intelligence.py` verifies:

- JSON graph summary and per-node annotations;
- unchanged legacy output without Intelligence;
- DOT summary, legend, and highlighting;
- Mermaid summary and priority classes;
- missing node references;
- untrusted label escaping.

## Review gate

A change is ready only after focused tests and the complete suite pass from a clean tree. Extracted patch packages should be removed before running the full suite so pytest does not collect duplicate test modules.
