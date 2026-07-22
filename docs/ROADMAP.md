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
- Expanded 48-technique ATT&CK catalog subset with matching behavior and LOLBin rules
- Threat-intelligence precision hardening and calibration corpus with CI gate
- Catalog/producer parity: every ATT&CK catalog entry has a built-in producer or an explicit rule-pack-only designation
- Repeatable performance benchmarks with a committed baseline and CI regression gate
- Rule-pack hardening: enforced validation, duplicate-ID checks (including built-in impersonation), per-pack limits, fixtures, and a strict `--rules-validate` gate
- Evidence correlation platform (Milestone 5): cross-case IOC database, relationship scoring, campaign clustering, timeline correlation, infrastructure reuse detection, shared payload detection, attribution hints, analyst views, persisted cross-case fingerprints/events, and `--correlation-search`

- Plugin SDK v1 (Milestone 6): stable public decoder/analyzer/detection/report APIs behind `titan_decoder.plugins.api`, plugin manifest with JSON Schema, semantic version compatibility and dependency constraints, deep validation (`--plugin-validate`), example plugins, and a complete developer guide
- Analyst Workbench (Milestone 7): `titan-workbench` terminal application — report library, decode-tree and interactive graph exploration with node navigation, IOC/detection/timeline/evidence browsers, correlation view, ranked cross-report search, investigation workspaces with notes/tags/status, and CSV/graph/ZIP-bundle exports
- Local AI Analyst (Milestone 8): `titan-analyst` — report-grounded evidence ledger with stable citations, deterministic question planning, citation-enforced validation, a tested local OpenAI-compatible backend (loopback-only by default), and a deterministic no-model default that doubles as the guaranteed fallback

Additional shipped engine expansion:

- ASCII85, Base58, Base91, raw Deflate, PowerShell EncodedCommand,
  JavaScript escape, and optional Brotli/Zstandard decoders.
- RFC/MIME, OOXML, script, LNK, optional 7z/RAR/ISO/CAB, deeper PE/ELF, and
  expanded image/audio/video steganography analyzers.
- Versioned Windows/Debian capability handshake, manual decoder parity,
  progress events, real timeouts, and cancellation.
- Hash-bound assurance adapters for isolated VM and provenance providers plus
  optional native Authenticode verification.
- Out-of-process manifest-plugin execution with resource bounds, offline
  network policy, and permission-scoped configuration disclosure.
- Deterministic Deep Scan, per-file assurance reports, and hash-addressed,
  recoverable, copy-by-default quarantine.
- Decoder/analyzer calibration v1 with a labeled corpus, confusion matrices,
  per-component metrics, and precision/recall gates.

## Highest-value next work

The original milestone plan and the engine-expansion pass are complete. Future
work should be driven by measured misses: larger representative calibration
corpora, OS-native sandbox adapters for plugin workers, additional signed-file
formats, richer memory-image analysis, and provider-specific VM integrations.
Any new parser or decoder should land with a labeled positive/negative corpus
slice and resource-bound regression tests.

## Enterprise-competitiveness track

Ordered by leverage. Each item ships incrementally behind Titan's existing
constraints: deterministic, bounded, offline-first, fail-closed.

1. **Detection content at scale.** YARA scanning of every artifact-graph
   node shipped (see DETECTION_AND_RISK.md); next: grow the built-in rule
   library and starter packs aggressively, expand the calibration corpus
   toward thousands of labeled cases, and publish per-rule precision/recall
   from the calibration gate.
2. **Malware config extraction.** Family identification plus C2/config
   recovery (addresses, keys, campaign ids) as isolated manifest plugins on
   the existing out-of-process worker substrate, with a documented extractor
   SDK and a seed set of extractors for prevalent families.
3. **Format coverage depth.** .NET assembly structure, MSI/NSIS/InnoSetup
   installers, OneNote, RTF exploit structures, Excel 4.0 XLM macros, VBA
   p-code, PDF stream filters with JavaScript extraction, Mach-O, APK/DEX,
   VHD/VHDX, and password-protected archives (`infected`). Every new parser
   lands with a labeled corpus slice and resource-bound regression tests.
4. **Service mode.** A `titan-server` deployment shape: REST API, work
   queue, horizontally scalable workers, artifact store, and hash-based
   dedup cache (reference architecture: CCCS Assemblyline), so Titan runs as
   pipeline infrastructure rather than a single-process CLI.
5. **Bounded emulation.** Instruction-budgeted, no-I/O emulation for
   shellcode (Unicorn-class) and sandboxed JavaScript evaluation for
   deobfuscation — deterministic and fail-closed by construction, extending
   static analysis past string-building obfuscation without becoming a
   sandbox.
6. **Proof and ecosystem.** Published benchmark runs against public corpora,
   a public accuracy dashboard fed by calibration output, third-party audit
   of the parsing surface (extending the fuzz harness), MISP/STIX export,
   and a community plugin registry. Positioning: forensic-grade,
   deterministic, offline-first, court-ready provenance.

## Local AI assistant (shipped as Milestone 8)

The requirements that guided the design — optional and disabled by
default, local/offline first, no autonomous network access, facts
separated from model inference, bounded input/output/time, graceful
deterministic fallback, and one fully working backend before multiple
adapters — are all implemented; see
[LOCAL_AI_ANALYST.md](LOCAL_AI_ANALYST.md). Additional backends (e.g.
ONNX with a concrete model and tokenizer contract) can be added behind
the existing `AnalystBackend` interface.
