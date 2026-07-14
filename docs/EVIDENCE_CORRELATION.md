# Evidence Correlation

Phase 5.1 introduces the deterministic foundation for correlating Titan analyses
across cases.

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

## Scope

Phase 5.1 provides models, storage, scoring, timeline normalization, and a
versioned report schema. CLI integration, campaign clustering, and analyst
views remain later Phase 5 work.
