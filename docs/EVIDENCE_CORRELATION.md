# Evidence Correlation

Phase 5 correlates Titan analyses across cases. Phase 5.1 delivered the
deterministic foundation (models, storage, scoring, timeline normalization);
the completed milestone adds campaign clustering, timeline correlation,
infrastructure reuse detection, shared payload detection, attribution hints,
analyst views, and CLI integration.

## Design guarantees

- Offline-first SQLite persistence.
- Stable identifiers derived from canonical JSON.
- Correlation occurs before the subject analysis is recorded, preventing
  self-matches.
- Relationship scores are deterministic and bounded from 0.0 to 1.0.
- Every score contribution is represented as evidence with source analysis
  references.
- Database rows preserve the full normalized analysis payload.
- Timeline timestamps normalize to UTC RFC 3339 form.
- The output contract is versioned as `correlation-report-v1.0`.

## Score components

The default relationship score is the weighted sum of:

| Component | Weight |
|---|---:|
| Shared indicators | 0.50 |
| Shared ATT&CK techniques | 0.20 |
| Shared threat tags | 0.15 |
| Decode-chain similarity | 0.15 |

Indicators intentionally receive the largest weight. ATT&CK techniques and
behavioral tags provide corroboration, while decode-chain similarity helps
surface related artifacts without being sufficient by itself to claim a
campaign.

## Milestone features

All features operate offline over the local correlation database and are
deterministic: re-running over the same inputs yields identical output,
including identifiers.

### Campaign clustering (`campaigns.py`)

Builds the pairwise relationship graph over recorded analyses with the
default scorer, keeps edges at or above `--campaign-min-score`
(default 0.45), and reports connected components as campaigns
(`campaign-clusters-v1.0`). Campaign IDs are stable digests of the sorted
member set.

### Timeline correlation (`timeline_correlation.py`)

Links events from *different* analyses that fall within
`--timeline-window-seconds` (default 300) of each other
(`timeline-correlation-v1.0`). Events sharing observable metadata values
(domain, IP, hash, host, user, …) form strong links; matching event kinds
alone form weaker ones. `None` and nested values are never compared, so
sparse events cannot false-match. Events come from DFIR evidence
(`evidence.events`), which carries real wall-clock timestamps.

### Infrastructure reuse (`infrastructure.py`)

Flags network-infrastructure indicators (domains, URLs, public IPs,
certificates, JA3/JA4, ASNs, nameservers, WHOIS emails) observed in more
than one recorded analysis (`infrastructure-reuse-v1.0`). Private IP
ranges are excluded by design: shared RFC 1918 addresses are noise, not
reuse.

### Shared payload detection (`payload_similarity.py`)

Fingerprints each report from node content hashes and the decode chain,
then scores pairs (`shared-payload-v1.0`). An exact content-hash match
contributes 0.55; fuzzy/import/resource hashes (when present) and
decode-chain overlap corroborate. Matches below
`--shared-payload-min-score` (default 0.35) are dropped.

### Cross-case persistence and search

Payload fingerprints and timeline events are persisted in the correlation
database (schema v2) alongside indicator records, so shared-payload and
timeline correlation operate across every recorded case — no in-process
report set is required. Timeline events are capped at a deterministic
2,000 per analysis. v1 databases upgrade in place on open; analyses
recorded before v2 lack stored fingerprints/events until re-analyzed.

`--correlation-search [TYPE:]VALUE` (repeatable) searches recorded
indicators across cases and exits without running an analysis. Matching is
exact on the normalized value and case-insensitive; results include each
match's evidence references (`correlation-search-v1.0`). The same query
API is available as
`titan_decoder.correlation.service.search_cases(db_path, queries)`.

### Attribution hints (`attribution.py`)

Combines infrastructure reuse, shared payloads, and ATT&CK/tag overlap
into per-pair hints (`attribution-hints-v1.0`). Hints are investigative
leads: every hint carries an explicit statement and the report carries a
disclaimer that hints are never actor identity claims.

### Analyst views (`views.py`)

`analyst_summary` condenses the full result into one view
(`analyst-correlation-view-v1.0`), rendered as JSON, Markdown, or a
self-contained HTML page with the machine-readable view embedded.

## CLI usage

```bash
titan cli --file sample.bin \
  --correlation-db cases.sqlite3 \
  --correlation-out correlation.json \
  --campaign-out campaigns.json \
  --attribution-hints-out hints.json \
  --analyst-correlation-out view.md --analyst-correlation-format markdown
```

Passing any Phase 5 flag runs the whole suite and embeds the sections in
the main report. `--correlation-no-record` correlates without persisting
the current analysis. The combined output contract is versioned as
`milestone-5-report-v1.0` (`schemas/milestone-5-report-v1.0.schema.json`).

The service entry point is
`titan_decoder.correlation.service.analyze_milestone5(report, db_path, ...)`;
report adapters live in `titan_decoder/correlation/adapters.py`.
