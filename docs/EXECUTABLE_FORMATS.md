# Executable format analysis

Titan performs deterministic structural analysis without loading or executing
the artifact. The Mach-O and DEX analyzers extend the existing PE and ELF
coverage and are enabled by default under the `analyzers.macho` and
`analyzers.dex` configuration keys.

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
