# CLI Reference

Titan exposes two console commands after installation:

- `titan` starts the interactive menu.
- `titan-decoder` runs the scriptable analysis pipeline.

The command-line interface is intentionally file- and pipeline-oriented. Run `titan-decoder --help` for the authoritative option list for the installed version.

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

## Graph formats

```bash
titan-decoder --file sample.bin --graph graph.json --graph-format json
titan-decoder --file sample.bin --graph graph.dot --graph-format dot
titan-decoder --file sample.bin --graph graph.mmd --graph-format mermaid
```

When Intelligence is present, all formats include graph-level assessment metadata and ranked-artifact annotations. See [GRAPH_EXPORTS.md](GRAPH_EXPORTS.md).

## Diagnostics and discovery

```bash
titan-decoder --doctor
titan-decoder --list-decoders
titan-decoder --list-analyzers
titan-decoder --list-rule-packs
titan-decoder --print-schema-version
```

These commands are side-effect-light and suitable for installation checks and CI diagnostics.
