# Graph Exports

Titan exports the analysis graph in JSON, Graphviz DOT, and Mermaid.

## Commands

```bash
titan cli --file sample.bin --graph graph.json --graph-format json
titan cli --file sample.bin --graph graph.dot --graph-format dot
titan cli --file sample.bin --graph graph.mmd --graph-format mermaid
```

## Legacy-compatible core

All formats preserve nodes and parent-child transformation edges. Without an Intelligence object, output retains the existing behavior.

## Intelligence annotations

When Intelligence is present:

- JSON metadata includes version, classification, score, confidence, recommendation, signal codes, and annotated-node count.
- Ranked graph nodes receive `intelligence` with rank, score, priority, reasons, and artifact name.
- DOT adds a graph summary, priority legend, highlighted fill colors, priority score, and thicker borders.
- Mermaid adds a summary node, class definitions, and ranked-node priority labels.

Priority colors are visualization aids; the numeric score and reasons remain authoritative.

## Safety

DOT labels escape quotes and backslashes. Mermaid labels neutralize pipes, quotes, line breaks, and HTML-sensitive angle brackets. Exporters must never insert untrusted previews as raw syntax.

## Consumer guidance

Consumers should ignore unknown additive fields. Use node IDs as graph identity and Intelligence rank only as presentation metadata.
