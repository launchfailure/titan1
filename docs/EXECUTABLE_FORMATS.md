# Executable format analysis

Titan performs deterministic structural analysis without loading, mounting, or
executing the artifact. Mach-O, DEX, and virtual-disk analysis extend the
existing PE and ELF coverage and are enabled by default under
`analyzers.macho`, `analyzers.dex`, and `analyzers.virtual_disk`.

## PE and .NET assemblies

PE analysis reports headers, sections, entropy, imports, Authenticode range,
overlay size, and structural anomalies. When data-directory entry 14 points to
a CLR runtime header, the same analyzer also validates and reports:

- CLR header/runtime versions, managed or native entry-point form, and
  IL-only, architecture, and strong-name flags;
- the bounded ECMA-335 metadata root and its `BSJB` signature;
- metadata stream names, offsets, sizes, and range validity;
- bounded string-heap previews plus the Module name and MVID when present;
- bounded row counts and schema-derived row ranges for all declared metadata
  tables, including Assembly, TypeDef, MethodDef, AssemblyRef, and
  ManifestResource;
- Assembly identity, version, culture, flags, public-key summary, and bounded
  AssemblyRef identities, versions, cultures, hashes, and public-key tokens;
- bounded ManifestResource ownership and embedded-resource ranges, with up to
  32 resources entering the ordinary recursive artifact graph;
- strong-name signature location and range validity.

Metadata is capped at 64 MiB, stream headers at 64, and table processing at the
64-bit valid-table mask. Titan does not load the CLR, resolve assemblies, or
execute managed initializers. Invalid ranges and truncated metadata fail closed
with stable anomaly codes in `pe_metadata.json`.

## Installer overlays

PE overlay inspection recognizes structurally valid NSIS `FirstHeader` records
and exact Inno Setup data-version signatures. It reports the family, bounded
overlay offsets and sizes, relevant NSIS flags/declared lengths, and the Inno
version and Unicode marker. Scanning is capped at 16 MiB and exact signatures
are required, so prose mentioning an installer family does not become format
evidence. Titan does not run an installer or claim to decompress its payloads;
full NSIS/Inno payload-table decoding remains future depth work.

## Mach-O

The analyzer accepts thin 32-bit and 64-bit, little-endian and big-endian
Mach-O files. It validates the complete load-command region before emitting
metadata, caps parsing at 2,048 commands and 1,024 sections, and reports:

- CPU, bitness, byte order, file type, flags, UUID, and entry-file offset;
- linked dynamic libraries;
- section names, segments, offsets, sizes, flags, and bounded entropy;
- invalid section ranges and load-command padding as anomalies.

Universal/fat containers are not yet expanded; each thin member can be
analyzed once extracted.

## Android DEX

The analyzer validates the 112-byte header, endian tag, declared file size,
and all primary table counts/offsets. It emits table metadata and up to 4,096
strings, with 4 KiB per-string and 2 MiB aggregate output limits. The string
artifact enters Titan's normal recursive graph, allowing URLs and other IOCs
embedded in DEX string data to be recovered without executing bytecode.

Malformed offsets, oversized tables, unterminated strings, and invalid ULEB128
prefixes fail closed or are skipped within the documented bounds.

## VHD and VHDX virtual disks

The `VirtualDisk` analyzer performs read-only inspection and never mounts an
image. For VHD it validates the 512-byte `conectix` footer checksum, format and
disk type, declared size, geometry, creator fields, and unique identifier.
Fixed VHD images receive bounded MBR partition-range validation; partitions up
to the structured-artifact limits enter Titan's recursive graph for IOC and
nested-format analysis. Protective MBRs lead into primary GPT validation:
Titan checks the GPT header and entry-array CRC32 values, declared usable
ranges, disk/partition GUIDs, UTF-16 partition names, and scans at most 128
entries from an entry array capped at 8 MiB.

For VHDX, Titan validates the file identifier, both redundant 4 KiB headers
with CRC-32C, sequence-number selection, log alignment/ranges, and both 64 KiB
region tables. BAT and metadata region GUIDs are identified, region alignment
and bounds are checked, and unknown required regions fail closed as structural
anomalies. The metadata table is bounded to 2,047 entries and reports validated
block size, virtual disk size/ID, logical and physical sector sizes, fixed/dynamic
flags, and parent requirements.

For self-contained images whose virtual size fits the configured artifact cap,
Titan scans at most 4,096 BAT entries and reconstructs at most 128 fully-present
or zero payload blocks. The resulting raw virtual disk and bounded MBR/GPT
partitions enter the recursive graph. Large images, undefined blocks, partial
differencing blocks, invalid/reserved states, and out-of-range physical blocks
remain metadata-only. Differencing-parent resolution, file-system walking, and
mounting are deliberately outside this parser boundary.
