# RTF Analysis

Titan recognizes Rich Text Format documents by their `rtf` header and performs
bounded static extraction. It does not render the document, invoke an OLE
server, execute embedded content, or repair malformed input.

The analyzer adds these artifacts to the normal provenance graph:

- `rtf_summary.json` — structural status, maximum group depth, object classes,
  suspicious control-word counts, extracted-object hashes, and truncation
  indicators;
- `rtf_text.txt` — normalized visible text with binary/object, picture, font,
  color, style, and metadata destinations excluded;
- `rtf_object_NNN.<type>` — decoded `objdata`, with embedded CFB/OLE, PE, ZIP,
  or PDF content carved from its first recognized signature when present.

Extracted text and objects pass through Titan's existing IOC, decoder,
analyzer, detection, risk, and Intelligence stages. Repeated object payloads
are deduplicated by SHA-256.

## Bounds and malformed input

RTF scanning uses the shared structured-analysis input, artifact-count,
per-artifact, and total-output limits. Group tracking is capped at 256 levels,
binary control payloads are skipped by declared length during structural
scanning, and extracted object bytes are capped before allocation grows beyond
the configured artifact limit. Unbalanced or excessively nested documents are
reported in the summary and fail closed without executing content.
