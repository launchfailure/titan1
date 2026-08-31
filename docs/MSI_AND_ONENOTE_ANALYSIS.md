# MSI and OneNote Analysis

Titan performs bounded, static inspection of Windows Installer databases and
OneNote section files. Neither analyzer invokes Windows Installer, OneNote,
custom actions, OLE servers, or recovered payloads.

## Windows Installer

The MSI analyzer requires a structurally valid Compound File Binary container
with both `_StringPool` and `_StringData` streams. It decodes MSI's packed CFB
stream names, bounded string-pool entries using the declared code page, and a
conservative custom-action execution surface. It emits:

- `msi_summary.json` with raw and decoded stream inventory, table names, code
  page, string and payload counts, source streams, hashes, storage status, and
  bounded custom-action evidence (table presence, sequence tables, Binary
  streams, and command-bearing strings);
- `msi_strings.txt` with deduplicated decoded strings;
- `msi_payload_NNN.<type>` for CFB/OLE, PE, ZIP, CAB, or PDF content recovered
  from bounded database streams.

Duplicate payloads are suppressed by SHA-256. Malformed streams fail closed.
The custom-action evidence is descriptive and does not claim that an action is
reachable or will execute. Full row-level table interpretation remains a
separate parser boundary. `TITAN-012` correlates a recognized MSI, an embedded executable, and a network
indicator; a normal support URL or an offline helper executable alone is not a
match.

## OneNote

The OneNote analyzer follows Microsoft's documented MS-ONESTORE structures:
the `.one` file-type and format GUIDs plus complete `FileDataStoreObject`
records with their header GUID, 64-bit length, zero reserved fields, padding,
and footer GUID. See the official [Header](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-onestore/2b394c6b-8788-441f-b631-da1583d772fd)
and [FileDataStoreObject](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-onestore/8806fd18-6735-4874-b111-227b83eaac26)
definitions.

It emits:

- `onenote_summary.json` with format, truncation, object offsets, types, sizes,
  hashes, and storage status;
- `onenote_strings.txt` with bounded ASCII and UTF-16 strings;
- `onenote_file_NNN.<type>` for complete embedded objects, typed as OLE, PE,
  ZIP, CAB, PDF, RTF, or generic binary.

`TITAN-013` requires a recognized OneNote section, a recovered executable, and
a network indicator. Empty notes and passive attachments remain non-matches.

## Resource and trust boundaries

Both analyzers use `max_structured_artifacts`,
`max_structured_total_size`, and `max_structured_artifact_size`. Stream/object
counts, decoded strings, paths, and previews are additionally capped. Recovered
artifacts enter Titan's ordinary provenance graph and are rescanned by the same
IOC, decoder, analyzer, detection, risk, and Intelligence stages.
