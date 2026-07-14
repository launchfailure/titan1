# Developer Guide

## Setup

See [CONTRIBUTING.md](../CONTRIBUTING.md) for environment setup and contribution requirements.

## Change workflow

1. Identify the owning subsystem and its report contract.
2. Add a focused failing test.
3. Implement the smallest deterministic change.
4. Add malformed-input and bound tests where bytes are processed.
5. Run focused tests, then the full suite.
6. Update user and developer documentation.
7. Review generated JSON, Markdown, HTML, DOT, or Mermaid output when relevant.

## CLI stages

The CLI is intentionally staged so orchestration behavior can be tested independently:

- configuration and early commands;
- input and evidence loading;
- engine analysis;
- evidence attachment;
- detections and risk;
- Intelligence attachment;
- optional enrichment;
- exporters and exit policy.

Avoid moving interpretation into the engine simply because the CLI currently calls both.

## Compatibility

Additive fields are preferred. Existing keys and meanings should not change silently. For incompatible changes, increment the relevant schema version and provide fixtures that lock the new behavior.

## Determinism checklist

- Sort unordered collections before serialization.
- Avoid timestamps in semantic hashes.
- Use stable tie breakers.
- Keep decoder/analyzer names stable.
- Do not call network services in deterministic stages.
- Test repeated execution equality.

## Security checklist

- Cap output before allocating large buffers.
- Bound archive counts and ratios.
- Escape untrusted text in DOT, Mermaid, HTML, and logs.
- Treat plugins and rule packs as code/configuration trust boundaries.
- Never make enrichment implicit.
