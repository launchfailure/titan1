# CLI Reference

Titan exposes one executable after installation:

- `titan` opens the native desktop workbench.
- `titan cli` accesses the advanced scriptable analysis pipeline through the
  same executable.

The command-line interface is intentionally file- and pipeline-oriented. Run `titan cli --help` for the authoritative option list for the installed version. For hands-on walkthroughs and report interpretation, see [USAGE.md](USAGE.md).

## Input modes

```bash
titan cli --file sample.bin
titan cli --batch ./samples --batch-pattern '*.bin'
```

`--file` analyzes one object. `--batch` walks matching files and writes one report per input. Input size, recursion, node, memory, and timeout limits still apply.

## Primary outputs

```bash
titan cli --file sample.bin --out report.json
titan cli --file sample.bin --jsonl-out events.jsonl
titan cli --file sample.bin --report-out case.md --report-format markdown
titan cli --file sample.bin --report-out case.html --report-format html
titan cli --file sample.bin --graph graph.json --graph-format json
```

Use `--stdout none` when a pipeline should not emit the full JSON report to standard output. Status messages are written to standard error; `--quiet` suppresses non-error status output.

## Analysis controls

```bash
titan cli --file sample.bin --profile fast
titan cli --file sample.bin --profile full --max-depth 8 --max-artifacts 200
titan cli --file sample.bin --trace --seed 1234
```

Profiles select coherent presets. Explicit flags override configuration where supported. Decision traces increase report size and are intended for debugging or reproducibility work.

## Deep scan and quarantine

```bash
titan cli --deep-scan ./incoming --offline --deep-scan-out summary.json
titan cli --deep-scan ./incoming --offline \
  --quarantine-verdict malicious --quarantine-action copy
titan cli --quarantine-list
titan cli --quarantine-restore RECORD_ID --quarantine-destination restored.bin
```

Deep Scan recursively performs static analysis and writes one report per file;
it never executes a sample. Quarantine is disabled unless a verdict is named.
`copy` is the default, while `move` removes an original only after a verified
vault copy. `suspicious` must be explicitly requested and should not be treated
as a confirmed-malware verdict. See
[DEEP_SCAN_AND_QUARANTINE.md](DEEP_SCAN_AND_QUARANTINE.md).

## Decoder/analyzer calibration

```bash
titan cli \
  --calibrate tests/fixtures/calibration/decoder-analyzer-v1.json \
  --calibration-out calibration.json
```

The report contains a confusion matrix, precision, recall, F1, specificity,
accuracy, per-component results, and the configured quality gate. The command
exits non-zero when the gate fails. See [CALIBRATION.md](CALIBRATION.md).

## Detections, Intelligence, and policy exits

```bash
titan cli --file sample.bin --enable-detections --out report.json
titan cli --file sample.bin --enable-detections --explain
titan cli --file sample.bin --intelligence-out intelligence.json
titan cli --file sample.bin --enable-detections --fail-on-risk-level HIGH
titan cli --file sample.bin --enable-detections --yara-rules rules/ --yara-rules extra.yar
```

The Intelligence object is attached to every normal report. Detection and risk inputs are richer when `--enable-detections` is set. `--fail-on-risk-level` is intended for CI and returns a non-zero status when the configured threshold is met or exceeded.

`--yara-rules` (repeatable, file or directory) scans every artifact-graph node — raw, decoded, and extracted content — with the given YARA rules; matches become `YARA:<namespace>:<rule>` detections and feed risk scoring. Requires the optional `yara-python` dependency, works fully offline, and is bounded and fail-closed. See [DETECTION_AND_RISK.md](DETECTION_AND_RISK.md).

## Evidence ingestion

```bash
titan cli --file sample.bin \
  --evidence dns:exports/dns.csv \
  --evidence proxy:exports/proxy.jsonl \
  --evidence firewall:exports/flows.csv \
  --evidence-timeline-out evidence.csv \
  --evidence-timeline-format csv
```

Supported kinds are `dns`, `proxy`, `firewall`, `vpn`, `auth`, `dhcp`, and `generic`. Evidence files are parsed before the potentially long byte-analysis stage so invalid paths fail early.

## IOC and forensic exports

```bash
titan cli --file sample.bin --ioc-out iocs.json --ioc-format json
titan cli --file sample.bin --ioc-out iocs.csv --ioc-format csv
titan cli --file sample.bin --ioc-out iocs.json --ioc-format misp
titan cli --file sample.bin --forensics-out forensics.json
```

IOC formats are export representations, not additional analysis passes.

## Enrichment and offline mode

```bash
titan cli --file sample.bin --enable-enrichment
titan cli --file sample.bin --offline --enable-enrichment
```

Enrichment is explicit and optional. `--offline` prevents network-backed enrichment and should be used for isolated or evidentiary environments.

## Cross-case correlation (Phase 5)

```bash
titan cli --file sample.bin \
  --correlation-db cases.sqlite3 \
  --correlation-out correlation.json \
  --campaign-out campaigns.json \
  --timeline-correlation-out timeline-links.json \
  --infrastructure-reuse-out infra.json \
  --shared-payload-out payloads.json \
  --attribution-hints-out hints.json \
  --analyst-correlation-out view.md --analyst-correlation-format markdown
```

Passing any of these flags runs the offline Phase 5 suite: the current
analysis is scored against every analysis recorded in the local SQLite
database (default `~/.titan_decoder/correlation.sqlite3`), campaigns are
clustered, infrastructure reuse and shared payloads are detected, and
evidence-backed attribution hints are derived. The sections are also
embedded in the main JSON report under `correlation`, `campaigns`,
`timeline_correlation`, `infrastructure_reuse`, `shared_payloads`, and
`attribution_hints`.

Tuning and behavior flags: `--correlation-min-score`,
`--campaign-min-score`, `--shared-payload-min-score`,
`--timeline-window-seconds`, and `--correlation-no-record` (correlate
without persisting the current analysis). The analyst view renders as
`json`, `markdown`, or `html`. See
[EVIDENCE_CORRELATION.md](EVIDENCE_CORRELATION.md).

Cross-case search runs standalone (no input file) and exits:

```bash
titan cli --correlation-db cases.sqlite3 --correlation-search c2.example
titan cli --correlation-db cases.sqlite3 --correlation-search domains:c2.example \
  --correlation-search urls:https://c2.example/gate.php
```

## Graph formats

```bash
titan cli --file sample.bin --graph graph.json --graph-format json
titan cli --file sample.bin --graph graph.dot --graph-format dot
titan cli --file sample.bin --graph graph.mmd --graph-format mermaid
```

When Intelligence is present, all formats include graph-level assessment metadata and ranked-artifact annotations. See [GRAPH_EXPORTS.md](GRAPH_EXPORTS.md).

## Plugins

```bash
titan cli --plugin-validate path/to/plugin
titan cli --plugin-list --plugin-dir examples/plugins
titan cli --file sample.bin --plugin-dir ~/my-plugins --enable-detections
```

`--plugin-validate` deep-validates a manifest plugin (manifest contract, API
compatibility, entry point, capabilities, and a bounded runtime probe) and
exits non-zero on failure; the probe executes plugin code in-process.
`--plugin-list` prints every discovered plugin, including load errors and the
active execution mode. Manifest plugins are isolated by default; legacy
single-file plugins and the explicit validation probe remain in-process.
`--plugin-dir` adds plugin search directories (repeatable) for both
standalone modes and analysis runs. See [PLUGIN_API.md](PLUGIN_API.md).

## Diagnostics and discovery

```bash
titan cli --doctor
titan cli --list-decoders
titan cli --list-analyzers
titan cli --list-rule-packs
titan cli --print-schema-version
```

These commands are side-effect-light and suitable for installation checks and
CI diagnostics. `--doctor` reports `ready` or `degraded`, imports every optional
format module to detect broken native installations, lists missing modules, and
prints the command needed to install the `formats` extra. Missing optional
libraries are warnings rather than a core-engine failure.
