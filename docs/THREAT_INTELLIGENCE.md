# Threat Intelligence Engine

The Threat Intelligence Engine maps decoded evidence to a versioned, offline
MITRE ATT&CK subset, identifies suspicious LOLBin usage, and emits behavioral
malware tags. It runs after detections and the Intelligence Layer, using the
same canonical IOC summary (report indicators merged with ingested evidence
indicators) so the indicators it cites stay consistent with every other
output.

Like the Intelligence Layer, it is deterministic: the same report always
produces the same assessment, with stable ordering for techniques, tactics,
findings, and relationships.

## Report contract

The report field is `threat_intelligence`:

- `version` — engine contract version (`1.0`).
- `catalog_version` — version of the bundled ATT&CK subset
  (`titan_decoder/threat_intel/data/attack_catalog.json`).
- `techniques` — ATT&CK technique findings, each with `technique_id`, `name`,
  `tactics`, `confidence`, supporting `evidence`, and `source_rules`. Sorted
  by descending confidence, then technique ID.
- `tactics` — sorted union of tactics across all techniques.
- `lolbins` — LOLBin findings with the executable, mapped technique IDs,
  matched suspicious terms, node IDs, and confidence.
- `malware_tags` — behavioral tags with category, reasons, node IDs, and
  confidence.
- `relationships` — deterministic node → technique/LOLBin/tag links with
  scores.
- `confidence` — overall assessment confidence in `[0, 1]`.
- `summary` — one-line human-readable summary.

Technique evidence comes from three sources: LOLBin findings, behavioral
regex rules over node text, and `attack_ids`/`mitre_attack` metadata on
triggered detections. Every built-in detection rule carries `attack_ids`,
and rule packs can declare them per rule (see
[DETECTION_AND_RISK.md](DETECTION_AND_RISK.md)). Only technique IDs present
in the bundled catalog are reported.

## Behavioral tags are not attribution

Malware tags describe observable behavior — `downloader-like`,
`script-stager-like`, `credential-theft-like`, `ransomware-impact-like`,
`host-discovery-like`, `living-off-the-land-chain` — and deliberately avoid
malware-family attribution, which Titan cannot support from content alone.

## Where it renders

- **JSON report** — the `threat_intelligence` object described above.
- **Case reports** (`--report-out`) — a "Threat Intelligence" section with an
  ATT&CK table, LOLBins, and behavioral tags, in both Markdown and HTML.
- **Graph exports** (`--graph`) — graph-level `threat_intelligence` metadata
  in JSON exports, plus per-node ATT&CK/LOLBin/tag annotations in JSON, DOT,
  and Mermaid outputs.

## Offline by design

The ATT&CK catalog ships with the package and is loaded from disk; no network
access is required or attempted, consistent with Titan's offline-first core.
The catalog is a curated 48-technique subset of MITRE ATT&CK Enterprise
focused on what payload analysis can actually evidence — execution,
defense-evasion, persistence, discovery, credential-access, impact, C2, and
delivery. It is the allow-list for every reported technique: catalog-integrity
tests (`tests/test_threat_catalog.py`) assert that IDs are unique and
well-formed and that every technique referenced by a behavior rule, LOLBin
rule, or detection `attack_ids` exists in the catalog, so producers and
catalog cannot drift apart.

The reverse direction is enforced too: every catalog technique must have a
built-in producer (behavior rule, LOLBin rule, or built-in detection
`attack_ids`) unless it is explicitly designated **rule-pack-only** in
`RULE_PACK_ONLY_TECHNIQUES` (`tests/test_threat_catalog.py`). Two techniques
carry that designation:

- **T1071 Application Layer Protocol** — C2-over-application-protocol cannot
  be evidenced deterministically from decoded content alone; rule packs with
  richer context may attribute it via `attack_ids`.
- **T1204 User Execution** — the parent-level form for packs that know user
  execution occurred but not the vector; built-ins attribute the specific
  T1204.002 Malicious File.

A companion test asserts the designated entries genuinely lack a built-in
producer, so the list cannot go stale in either direction.

## Precision semantics

Rules are written so that indicators alone never become behavioral findings:

- A bare URL is an IOC, not evidence of T1105 Ingress Tool Transfer; the
  network-transfer behavior rule requires a retrieval verb
  (`DownloadString`, `Invoke-WebRequest`, `curl`, `wget`, …).
- LOLBin names that are also everyday words need context. `hh` and `at`
  require the literal `.exe` form; `cmd` fires on `cmd.exe`, or on bare
  `cmd` only when an invocation term (`/c `, `/k `) is present in the same
  node (`bare_requires_term` on `LOLBinRule`).
- The `downloader-like` tag requires observed retrieval behavior in node
  content; URL indicators only corroborate (raising confidence), they never
  create the tag on their own.
- Overall assessment confidence is anchored to the strongest individual
  finding, with bounded increments for corroboration and source diversity —
  it cannot substantially exceed what any single finding supports, and a
  single weak finding stays below 0.5.
- T1486 Data Encrypted for Impact requires ransom-note language (`ransom`,
  `decryptor`, "decrypt/restore/recover your files"); the word "encrypted"
  alone ("files are encrypted at rest") is never evidence of impact, and
  shadow-copy deletion maps to T1490 Inhibit System Recovery, not T1486.
- T1059.007 JavaScript requires Windows Script Host markers (`jscript`,
  `new ActiveXObject(`, `.jse`); prose mentioning web "JavaScript" does not
  fire.
- T1566.001 Spearphishing Attachment requires a decoded MIME
  `Content-Disposition: attachment` header naming an executable, script, or
  container payload extension; benign attachment types (`.pdf`, `.docx`) do
  not match.

## Calibration corpus

`tests/fixtures/threat_intel/calibration-v1.json` is the deterministic
calibration corpus, mirroring the Intelligence Layer's
(`docs/INTELLIGENCE_LAYER.md`). Each case includes:

- `kind` — `benign` or `malicious`.
- `report` (and optionally `detections`) — the exact engine input.
- `expected` — the pinned output: `confidence`, ordered `technique_ids`,
  `tactics`, `lolbin_executables`, and `malware_tags`.

`tests/test_threat_calibration.py` asserts every case exactly, plus corpus
invariants: benign cases must expect a completely clean assessment
(confidence `0.0`, no findings), malicious cases at least one finding.
Benign cases cover prose containing URLs and everyday words that overlap
rule vocabulary ("cmd", "at", "hh:mm"), so false-positive regressions fail
CI.

Changing behavior rules, LOLBin rules, tagging, or confidence formulas will
usually change corpus expectations. That is deliberate: regenerate the
expected values, review the diff case by case (especially that benign cases
stay clean), and commit the corpus change alongside the rule change.

## Tests

```bash
python -m pytest tests/test_threat_intelligence.py \
  tests/test_threat_calibration.py \
  tests/test_threat_cli_wiring.py \
  tests/test_threat_graphs.py \
  tests/test_threat_case_reports.py
```
