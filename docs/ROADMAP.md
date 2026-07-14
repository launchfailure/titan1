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
- Intelligence v1.0 schema, compatibility tests, and calibration corpus
- Intelligence in Markdown/HTML case reports
- Intelligence annotations in JSON/DOT/Mermaid graph exports
- Evidence-backed MITRE ATT&CK mappings, LOLBin identification, and behavioral malware tags (Threat Intelligence Engine)
- ATT&CK technique metadata (`attack_ids`) on built-in detection rules and rule packs
- Repeatable performance benchmarks with a committed baseline and CI regression gate

## Highest-value next work

1. Strengthen rule packs with duplicate-ID checks, fixtures, and limits.
2. Improve cross-source evidence correlation while preserving provenance.
3. Expand the bundled ATT&CK catalog subset.

## Optional local AI assistant

Build this after the deterministic report contract is stable.

Planned capabilities:

- Summarize a completed report
- Explain nodes, signals, and provenance
- Draft an analyst handoff
- Answer questions with node-ID or signal-code references
- Suggest evidence-backed next steps

Requirements:

- Optional and disabled by default
- Local/offline first
- No automatic execution or autonomous network access
- Clear separation between Titan facts and model inference
- Bounded input, output, time, and memory
- Graceful fallback to deterministic output
- A fully working backend before adding multiple adapters

Potential backends include llama.cpp-compatible local runtimes and OpenAI-compatible local endpoints. ONNX support requires choosing a concrete model and tokenizer contract.

Recommended order:

Stable local-model interface → one tested backend → analyst chat UI.
