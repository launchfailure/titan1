# Deep Scan and Recoverable Quarantine

Deep Scan recursively applies Titan's static decoder, analyzer, detection, and
six-control assurance pipeline to a file or directory. It does not execute
samples and is not a real-time antivirus engine.

## Safe defaults

- Directory traversal is deterministic and does not follow symlinks by default.
- Per-file size, total-byte, file-count, recursion, node, time, memory, archive,
  and decompression limits remain active.
- Quarantine is disabled unless a verdict is explicitly named.
- The default quarantine action is `copy`; original evidence remains untouched.
- `move` removes the source only after the vault copy passes SHA-256
  verification.
- `SUSPICIOUS` is never quarantined unless it is explicitly selected.
- `INDETERMINATE` and `NO_MALICIOUS_EVIDENCE` are not safety claims.

## CLI workflow

Scan offline and write a summary plus one JSON report per file:

```bash
titan-decoder --deep-scan ./incoming --offline \
  --deep-scan-reports ./scan-reports \
  --deep-scan-out ./scan-summary.json
```

Copy confirmed malicious results into the default vault:

```bash
titan-decoder --deep-scan ./incoming --offline \
  --quarantine-verdict malicious --quarantine-action copy
```

Adding `--quarantine-verdict suspicious` expands policy to lower-confidence
results and should be used only when investigation procedures call for it.
`--quarantine-action move` is destructive to the source path and must be an
explicit operator choice.

## Vault and restoration

The default root is `~/.titan_decoder/quarantine`, configurable with
`quarantine_dir` or `--quarantine-dir`. Objects are stored by SHA-256 and each
quarantine event has a separate record containing the original path, verdict,
size, timestamp, report path, requested action, and source-removal outcome.

```bash
titan-decoder --quarantine-list
titan-decoder --quarantine-restore RECORD_ID \
  --quarantine-destination ./restored/sample.bin
```

Restore refuses to replace an existing destination unless
`--quarantine-overwrite` is supplied, and verifies the stored object hash before
writing. The vault is not encrypted; protect it with operating-system access
controls and evidence-retention policy.

## Native Windows workbench

Choose **File Analysis**, then **Deep Scan Folder**. **Scan Only** leaves the
source tree untouched. **Scan + Quarantine** copies only `MALICIOUS` verdicts
into the Debian-side vault. The operation uses the same versioned WSL backend,
streams progress, and can be cancelled with Escape.

## Configuration bounds

```json
{
  "deep_scan_max_files": 10000,
  "deep_scan_max_total_bytes": 10737418240,
  "deep_scan_follow_symlinks": false,
  "max_data_size": 52428800,
  "quarantine_dir": null
}
```

Quarantine is a response workflow, not proof that every malicious file was
found. Preserve original evidence and use an approved isolated VM when dynamic
behavior is required.
