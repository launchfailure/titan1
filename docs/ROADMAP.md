# Titan Decoder Engine Roadmap

This roadmap separates shipped features from planned work.

## Shipped

- Recursive decoder/analyzer graph
- Provenance, hashes, entropy, and transformation confidence
- Structural PDF and OLE/CFB parsing
- IOC extraction and evidence ingestion
- Detection rules and risk scoring
- Resource limits and offline guard
- Deterministic Intelligence Layer

## Highest-value next work

1. Formalize the `intelligence` report schema and compatibility tests.
2. Build a deterministic intelligence calibration corpus.
3. Add intelligence to Markdown/HTML case reports.
4. Add intelligence annotations to JSON/DOT/Mermaid graphs.
5. Add evidence-backed MITRE ATT&CK mappings.
6. Add repeatable performance benchmarks before optimization.
7. Strengthen rule packs with schema versions, duplicate-ID checks, fixtures, and limits.
8. Improve cross-source evidence correlation while preserving provenance.

## Optional local AI assistant

Build this after the deterministic report contract is stable.

Planned capabilities:

- Summarize a completed report
- Explain nodes, signals, and provenance
- Draft an analyst handoff
- Answer questions with node-ID or signal-code references
- Suggest evidence-backed next steps

Recommended order:

Documentation/schema → calibration tests → report/graph integration → ATT&CK mapping → benchmarks → stable local-model interface → one tested backend → analyst chat UI.
