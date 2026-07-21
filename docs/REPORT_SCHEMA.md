# Report Schema

Titan's primary JSON report is the contract between analysis, interpretation, export, and downstream tooling.

## Major sections

- `meta` — engine version, analysis identity, and run metadata.
- `run_manifest` — configuration and reproducibility context.
- `node_count` and `nodes` — transformation graph.
- `iocs` — normalized indicator summary.
- `evidence` — normalized events, indicators, pivots, links, and entity hints.
- `detections` — triggered rules.
- `risk_assessment` — score, level, and reasons.
- `intelligence` — versioned analyst summary.
- `threat_intelligence` — versioned ATT&CK techniques, LOLBins, behavioral tags, and relationships.
- `enrichment` — optional provider output.

The additive `analysis_outcome` section records decoding coverage and opaque
terminal payloads. `static_analysis` records offline provider/rule coverage,
`assurance_providers` records bounded, hash-bound adapter outcomes, and
`assurance` contains the six-control fail-closed verdict and blockers. Provider
errors remain explicit status entries; they never become an implicit pass.

## Versioning

The primary report schema version is defined in the engine. The Intelligence sub-object has its own JSON Schema and compatibility tests because it is consumed independently.

## Compatibility rules

- Additive optional fields are preferred.
- Removing a key, changing its type, or changing semantic meaning requires a version review.
- Arrays with semantic order must remain deterministic.
- Downstream consumers should tolerate unknown additive fields.
- Strict mode validates required report invariants.

## Node identity

Node IDs are local to one analysis. SHA-256 identifies content; provenance and parent IDs identify derivation. Do not use a node ID alone as a cross-run content identity.
