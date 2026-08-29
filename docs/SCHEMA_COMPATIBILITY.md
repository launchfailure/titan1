# Schema and Contract Compatibility Policy

The JSON report Titan emits is a **versioned, guaranteed contract**. Downstream
tools (SIEM ingestion, dashboards, correlation pipelines) build against it, so
its shape does not drift silently.

## Primary report contract

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

The strict CLI validates newly emitted reports against the current schema. The
read-only Analyst Workbench is intentionally more tolerant: its frozen v1.0
fixture locks support for top-level `analysis_id`, `root_hash`, and `risk`, plus
legacy `node_id`/`parent_id` graph identity. Saving or exporting never rewrites
the source report.

## Versioned contract inventory

| Contract | Current version | Reader policy | Migration policy |
|---|---:|---|---|
| Primary report (`docs/report.schema.json`) | 1.2 | Workbench reads frozen v1.0 shapes; strict validation targets current 1.2 | Additive minor changes; breaking changes require a new major and an explicit converter |
| Analyst workspace | 1.0 | Missing optional v1 fields and unknown additive entry fields are tolerated | Loading v1.0 and saving emits the current `analyst-workspace-v1.0` envelope |
| Plugin manifest | 1.0 | Manifest schema is exact; declared Plugin API 1.x is compatible when it does not require a newer minor | Incompatible manifest schemas are rejected; install a compatible plugin release |
| Plugin API | 1.2 | Original single-file 1.0 decoders/analyzers and manifest plugins from earlier 1.x minors remain supported | A major change requires a parallel API and documented porting path |
| Plugin catalog | 1.0 | Catalog validation is version-exact | Regenerate or migrate the catalog before loading a future version |
| Intelligence object | 1.0 | JSON Schema validation is version-exact; unknown additive fields are allowed where declared | Breaking changes require a new schema file and calibration fixtures |
| Correlation report | 1.0 | Validation requires the current v1.0 identifier | Migrate before ingestion; never reinterpret an unknown version silently |
| Milestone-5 report | 1.0 | Validation targets the named v1.0 schema | A new contract version requires a parallel schema and adapter |
| Local AI analyst response | 1.0 | Validation targets the named v1.0 response schema | Responses with unknown versions fail closed and must be regenerated or converted |
| Analyst case bundle | 1.0 | Bundle manifests identify `analyst-bundle-v1.0`; contained report readers follow the report policy above | Unpack and rebuild with a future writer; source reports remain unchanged |

The schemas in `schemas/` and the primary report schema are the authoritative
machine-readable definitions. Runtime formats without a standalone schema use
their emitted `schema_version` constant and focused contract tests.

## Change and migration rules

1. Optional additive fields use a minor version when the contract carries a
   `MAJOR.MINOR` version. Readers must ignore fields they do not understand.
2. Removing or renaming fields, changing types or meanings, or adding required
   fields is breaking and requires a new major contract alongside the old one.
3. A reader may be tolerant only where the table says so. Version-exact readers
   reject unknown contracts rather than guessing.
4. Migrations are explicit and non-destructive: read the old artifact, emit a
   new artifact, preserve the original, and test both with frozen fixtures.
5. Each supported legacy version needs a committed fixture exercised in Linux
   and Windows CI. Dropping a fixture is a compatibility decision that belongs
   in release notes and the changelog.
