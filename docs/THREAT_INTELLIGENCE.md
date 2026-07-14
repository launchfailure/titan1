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

## Tests

```bash
python -m pytest tests/test_threat_intelligence.py \
  tests/test_threat_cli_wiring.py \
  tests/test_threat_graphs.py \
  tests/test_threat_case_reports.py
```
