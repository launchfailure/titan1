# CLI Reference

Titan exposes two console commands after installation:

- `titan` starts the interactive menu.
- `titan-decoder` runs the scriptable analysis pipeline.

The command-line interface is intentionally file- and pipeline-oriented. Run `titan-decoder --help` for the authoritative option list for the installed version. For hands-on walkthroughs and report interpretation, see [USAGE.md](USAGE.md).

## Input modes

```bash
titan-decoder --file sample.bin
titan-decoder --batch ./samples --batch-pattern '*.bin'
```

`--file` analyzes one object. `--batch` walks matching files and writes one report per input. Input size, recursion, node, memory, and timeout limits still apply.

## Primary outputs

```bash
titan-decoder --file sample.bin --out report.json
titan-decoder --file sample.bin --jsonl-out events.jsonl
titan-decoder --file sample.bin --report-out case.md --report-format markdown
titan-decoder --file sample.bin --report-out case.html --report-format html
titan-decoder --file sample.bin --graph graph.json --graph-format json
```

Use `--stdout none` when a pipeline should not emit the full JSON report to standard output. Status messages are written to standard error; `--quiet` suppresses non-error status output.

## Analysis controls

```bash
titan-decoder --file sample.bin --profile fast
titan-decoder --file sample.bin --profile full --max-depth 8 --max-artifacts 200
titan-decoder --file sample.bin --trace --seed 1234
```

Profiles select coherent presets. Explicit flags override configuration where supported. Decision traces increase report size and are intended for debugging or reproducibility work.

## Detections, Intelligence, and policy exits

```bash
titan-decoder --file sample.bin --enable-detections --out report.json
titan-decoder --file sample.bin --enable-detections --explain
titan-decoder --file sample.bin --intelligence-out intelligence.json
titan-decoder --file sample.bin --enable-detections --fail-on-risk-level HIGH
```

The Intelligence object is attached to every normal report. Detection and risk inputs are richer when `--enable-detections` is set. `--fail-on-risk-level` is intended for CI and returns a non-zero status when the configured threshold is met or exceeded.

## Evidence ingestion

```bash
titan-decoder --file sample.bin \
  --evidence dns:exports/dns.csv \
  --evidence proxy:exports/proxy.jsonl \
  --evidence firewall:exports/flows.csv \
  --evidence-timeline-out evidence.csv \
  --evidence-timeline-format csv
```

Supported kinds are `dns`, `proxy`, `firewall`, `vpn`, `auth`, `dhcp`, and `generic`. Evidence files are parsed before the potentially long byte-analysis stage so invalid paths fail early.

## IOC and forensic exports

```bash
titan-decoder --file sample.bin --ioc-out iocs.json --ioc-format json
titan-decoder --file sample.bin --ioc-out iocs.csv --ioc-format csv
titan-decoder --file sample.bin --ioc-out iocs.json --ioc-format misp
titan-decoder --file sample.bin --forensics-out forensics.json
```

IOC formats are export representations, not additional analysis passes.

## Enrichment and offline mode

```bash
titan-decoder --file sample.bin --enable-enrichment
titan-decoder --file sample.bin --offline --enable-enrichment
```

Enrichment is explicit and optional. `--offline` prevents network-backed enrichment and should be used for isolated or evidentiary environments.

## Cross-case correlation (Phase 5)

```bash
titan-decoder --file sample.bin \
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
titan-decoder --correlation-db cases.sqlite3 --correlation-search c2.example
titan-decoder --correlation-db cases.sqlite3 --correlation-search domains:c2.example \
  --correlation-search urls:https://c2.example/gate.php
```

## Graph formats

```bash
titan-decoder --file sample.bin --graph graph.json --graph-format json
titan-decoder --file sample.bin --graph graph.dot --graph-format dot
titan-decoder --file sample.bin --graph graph.mmd --graph-format mermaid
```

When Intelligence is present, all formats include graph-level assessment metadata and ranked-artifact annotations. See [GRAPH_EXPORTS.md](GRAPH_EXPORTS.md).

## Plugins

```bash
titan-decoder --plugin-validate path/to/plugin
titan-decoder --plugin-list --plugin-dir examples/plugins
titan-decoder --file sample.bin --plugin-dir ~/my-plugins --enable-detections
```

`--plugin-validate` deep-validates a manifest plugin (manifest contract, API
compatibility, entry point, capabilities, and a bounded runtime probe) and
exits non-zero on failure; the probe executes plugin code in-process.
`--plugin-list` prints every discovered plugin, including load errors.
`--plugin-dir` adds plugin search directories (repeatable) for both
standalone modes and analysis runs. See [PLUGIN_API.md](PLUGIN_API.md).

## Diagnostics and discovery

```bash
titan-decoder --doctor
titan-decoder --list-decoders
titan-decoder --list-analyzers
titan-decoder --list-rule-packs
titan-decoder --print-schema-version
```

These commands are side-effect-light and suitable for installation checks and CI diagnostics.
