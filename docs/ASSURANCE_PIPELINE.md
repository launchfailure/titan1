# Assurance Pipeline

Titan's assurance layer answers a narrower and more defensible question than
"is this file safe?": **did every configured, applicable control complete
without finding malicious evidence?** No static or dynamic analyzer can prove
absolute safety, so Titan never emits a `SAFE` verdict.

## Verdicts

| Verdict | Meaning |
|---|---|
| `MALICIOUS` | A malicious hash or VM behavior was confirmed. |
| `SUSPICIOUS` | Static rules or VM behavior produced suspicious evidence. |
| `NO_MALICIOUS_EVIDENCE` | Every applicable control passed; this is not a safety guarantee. |
| `INDETERMINATE` | At least one required control failed or was unavailable. |

## Six controls

1. **Complete decoding** — every branch reached a readable or recognized end.
2. **Format validation** — terminal artifacts were validated by a parser or are
   readable text.
3. **No opaque payloads** — no unknown binary or encoded terminal remains.
4. **Static analysis** — hashing, parsers, IOC extraction, built-in rules, and
   active-content patterns completed offline.
5. **Isolated VM analysis** — required for recognized executable or active
   content; not applicable to ordinary inert data.
6. **Trusted provenance** — a configured trusted hash or hash-bound source
   attestation verifies origin.

Each control reports `pass`, `fail`, `unavailable`, or `not_applicable`.
`NO_MALICIOUS_EVIDENCE` is allowed only when all six controls are either
`pass` or legitimately `not_applicable`.

## Configuration

The workbench and CLI run the offline static suite automatically when
`enable_assurance` is true. Optional provider paths use these configuration
keys:

```json
{
  "enable_assurance": true,
  "enable_yara": true,
  "yara_rules_path": "/opt/titan/rules/local.yar",
  "malicious_hashes_path": "/opt/titan/trust/malicious-sha256.txt",
  "trusted_hashes_path": "/opt/titan/trust/known-good-sha256.txt",
  "sandbox_attestations_dir": "/opt/titan/attestations/sandbox",
  "provenance_attestations_dir": "/opt/titan/attestations/provenance"
}
```

Hash files contain one SHA-256 per line with an optional label after a space.
Blank lines and lines beginning with `#` are ignored. These files and the
attestation directories are trust roots: protect them from untrusted writers.
If YARA is explicitly enabled but the library or rules are unavailable, the
static control becomes `unavailable` and the assessment fails closed.

## VM attestation contract

Titan does not execute hostile samples on the workstation. A separately
managed VM sandbox writes `<sha256>.json` into the configured directory. Titan
accepts the result only when the filename and embedded `sample_sha256` match,
the schema is `1.0`, the run completed, and isolation is explicitly `vm` or
`virtual_machine`.

```json
{
  "schema_version": "1.0",
  "sample_sha256": "<64 lowercase hex characters>",
  "completed": true,
  "isolation": "vm",
  "verdict": "no_malicious_behavior",
  "provider": "internal-sandbox",
  "behaviors": []
}
```

Recognized verdicts are `no_malicious_behavior` (or `clean`), `suspicious`,
and `malicious`. Containers and WSL are not accepted as VM isolation claims.

## Provenance attestation contract

A provenance provider may write a hash-bound document when it has verified a
digital signature or trusted source identity:

```json
{
  "schema_version": "1.0",
  "sample_sha256": "<64 lowercase hex characters>",
  "trusted": true,
  "verification_method": "authenticode",
  "identity": "Example Software Publisher"
}
```

Titan consumes the attestation; signature verification belongs in the trusted
provider that creates it. An unsigned JSON file in a writable directory is not
meaningful provenance.
