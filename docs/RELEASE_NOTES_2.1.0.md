# Titan Decoder v2.1.0 — Depth, extensibility, and analyst workflows

Titan 2.1.0 packages the capability and assurance work accumulated after the
2.0.2 reliability release. The release remains deterministic, bounded, and
offline-first while adding deeper calibration, analyst workflows, plugin and
service surfaces, and stronger operational controls.

## Detection and parser depth

- Live-registry detection calibration with multiple positives and targeted
  benign near-misses for every built-in rule, including hidden-media
  `TITAN-008` and scheduled-task persistence `TITAN-009`.
- First-class bounded YARA scanning across every artifact-graph node, with a
  calibrated starter pack and risk-scoring integration.
- Decoder/analyzer calibration derived from the live registry, with recognition
  and extraction metrics plus malformed/truncated analyzer cases.
- New ASCII85, Base58, Base91, raw Deflate, PowerShell EncodedCommand,
  JavaScript escape, Brotli, and Zstandard decoders.
- Expanded email, OOXML, script, LNK, archive, executable, and steganography
  analysis with stricter false-positive boundaries.

## Investigation workflows

- Evidence correlation with persisted cross-case fingerprints, campaign and
  infrastructure views, timeline correlation, and correlation search.
- Plugin SDK v1 with versioned contracts, manifest validation, dependency and
  permission checks, and isolated worker execution.
- Analyst Workbench and native Windows desktop workflows, including Deep Scan,
  report exploration, evidence navigation, and recoverable quarantine.
- Local AI Analyst with citation-enforced, report-grounded answers and a
  deterministic no-model fallback.
- Loopback-only service mode with bounded request handling and deterministic
  artifact storage.

## Assurance and supply chain

- Hash-bound assurance adapters, bounded plugin workers, and explicit offline
  network policy.
- Reproducible benchmark and proof artifacts with CI freshness gates.
- Full optional test environment across Python 3.10–3.13; skipped tests now
  fail CI.
- Deterministic CycloneDX SBOM and Sigstore-enabled GitHub release workflow.
- Parser audit scope and source hashes prepared for independent assessment;
  Titan does not claim that the external review has occurred.

## Verification snapshot

- 858 tests pass with zero skips on the supported CI matrix.
- Coverage is approximately 79%, above the enforced 70% floor.
- Bounded fuzzing, performance regression, lint, type-check, and proof
  freshness gates pass on `main`.

## Release procedure

After the release-preparation pull request is merged and `main` is green:

```console
git fetch origin
git tag -a v2.1.0 -m "Titan Decoder v2.1.0 — depth, extensibility, and analyst workflows" origin/main
git push origin v2.1.0
```

The tag triggers the release workflow, which verifies the SBOM, builds
reproducible distributions, signs them with Sigstore, and creates the GitHub
Release. PyPI publishing remains opt-in.
