# Phase 2 — Intelligence in Case Reports

Phase 2 integrates the existing deterministic Intelligence Layer result into
Markdown and HTML case reports.

## Output

When `report["intelligence"]` is present, case reports now show:

- classification;
- intelligence score;
- confidence;
- Intelligence contract version;
- analyst recommendation;
- ordered top signals and evidence;
- the five highest-priority artifacts.

The case-report builder copies the existing Intelligence result. It does not
recompute scores or rankings, so JSON, Markdown, and HTML remain consistent.

## Compatibility

Reports created without an `intelligence` object keep the previous layout and
do not display an empty Intelligence section.

HTML rendering escapes Intelligence content because previews, artifact names,
rule names, and evidence can originate from untrusted samples.

## Test command

```bash
python -m pytest   tests/test_intelligence.py   tests/test_intelligence_contract.py   tests/test_case_report_intelligence.py
```

Then run the complete suite:

```bash
python -m pytest
```

## Manual smoke test

```bash
titan-decoder --file sample.bin   --enable-detections   --report-out case-report.md   --report-format markdown   --out report.json

titan-decoder --file sample.bin   --enable-detections   --report-out case-report.html   --report-format html   --out report.json
```
