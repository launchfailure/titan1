# Report Schema Compatibility Policy

The JSON report Titan emits is a **versioned, guaranteed contract**. Downstream
tools (SIEM ingestion, dashboards, correlation pipelines) build against it, so
its shape does not drift silently.

## The contract

- The authoritative schema is [`report.schema.json`](report.schema.json)
  (JSON Schema, draft 2020-12).
- Every report carries the schema version in two places:
  `meta.schema_version` and `run_manifest.tool.schema_version`. Both equal the
  `SCHEMA_VERSION` constant in `titan_decoder/core/engine.py`.
- **CI validates every emitted report against the schema**
  (`tests/test_schema_contract.py`) across a range of inputs. A report the
  schema does not allow fails the build.
- The schema's `const` version and the code's `SCHEMA_VERSION` are asserted to
  match, so the schema cannot be edited without a version bump and vice versa.

## Versioning (`MAJOR.MINOR`)

The schema version is `MAJOR.MINOR`.

- **MINOR bump** — additive, backward-compatible changes: new optional fields
  on existing objects, new top-level optional keys. A consumer written for an
  earlier minor version keeps working (it just ignores the new fields). Objects
  use `additionalProperties: true` specifically to make additive change safe.
- **MAJOR bump** — breaking changes: removing or renaming a field, changing a
  field's type, or making an optional field required. These require a deliberate
  version bump and a note in the changelog.

Current version: **1.2**.

## Change history

| Version | Change |
|---------|--------|
| 1.0     | Initial report contract. |
| 1.1     | Added `run_manifest`, evidence block, decision trace. |
| 1.2     | Added first-class per-node `provenance` and `artifact_name` (additive). |

## How to change the schema

1. Make the engine change.
2. Update `report.schema.json` to describe the new shape.
3. Bump `SCHEMA_VERSION` in `engine.py` (MINOR for additive, MAJOR for
   breaking) and the `const` in the schema (both places).
4. Add a row to the change-history table above.
5. `pytest tests/test_schema_contract.py` must pass — it re-validates emitted
   reports and enforces the version-lockstep check.

## Guarantee to downstream consumers

Within a MAJOR version, a report produced by a newer MINOR release validates
against the older MINOR schema for every field the older schema knew about.
Pin to a MAJOR version; treat unknown fields as forward-compatible additions.
