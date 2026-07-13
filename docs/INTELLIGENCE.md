# Titan Intelligence Layer

Titan's Intelligence Layer is a deterministic, dependency-free analysis stage that explains why decoded content deserves attention and which nodes an analyst should review first.

## Implemented now

- Deterministic 0–100 intelligence scoring
- Analyst-oriented classifications
- Explainable scored signals
- Prioritized decoded artifacts
- `--explain` human-readable output
- `--intelligence-out` JSON export
- Offline operation with no added runtime dependencies

The current layer is heuristic and deterministic. It is **not** a generative AI model and does not upload report data.

## Classifications

| Score | Classification |
|---:|---|
| 0–15 | `CLEAN` |
| 16–35 | `LOW_RISK_ARTIFACT` |
| 36–60 | `SUSPICIOUS_OBJECT` |
| 61–80 | `HIGH_RISK_PAYLOAD` |
| 81–100 | `LIKELY_MALICIOUS` |

## CLI examples

```bash
titan-decoder --file suspicious.bin --enable-detections --explain --out report.json
```

```bash
titan-decoder --file suspicious.bin --enable-detections \
  --intelligence-out intelligence.json --out report.json
```

`--explain` writes to stderr so JSON stdout remains pipeline-safe.

## Local AI assistant roadmap

A future optional local assistant may summarize reports, answer questions about nodes and provenance, and draft analyst handoffs.

Requirements:

- Optional and disabled by default
- Local/offline first
- No automatic execution or autonomous network access
- Clear separation between Titan facts and model inference
- Bounded input, output, time, and memory
- Graceful fallback to deterministic output
- A fully working backend before adding multiple adapters

Potential backends include llama.cpp-compatible local runtimes and OpenAI-compatible local endpoints. ONNX support requires choosing a concrete model and tokenizer contract.
