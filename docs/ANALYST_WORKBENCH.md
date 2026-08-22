# Analyst Workbench (Milestone 7)

The Analyst Workbench is a terminal application for exploring completed
Titan JSON reports:

```bash
titan workbench        # or: python -m titan_decoder.workbench.app
```

It sits strictly *above* the deterministic engine: reports are loaded
read-only, and the workbench never re-analyzes, reinterprets, or alters
forensic findings. Annotations live in a separate workspace file.

## Interface decision

The milestone plan left open whether the workbench should be a local web
application, a desktop application, or something else. It is a **terminal
application**, for the same reasons the rest of Titan is: it preserves the
offline-first, dependency-light guarantees (no server process, no browser
stack, nothing listening on a socket in an evidentiary environment), works
over SSH and in Codespaces, and reuses the injectable-I/O testing model the
interactive console established. A web front end can be layered on later
without changing the underlying models, search, or export modules.

## Capabilities

- **Report library** `[1]`/`[2]` — load one JSON report or every report in a
  directory; switch the active report. Unreadable files are skipped with a
  message, never fatally.
- **Report overview** `[3]` — analysis ID, root hash, classification, risk,
  node/IOC/detection counts, relationships, campaigns.
- **Decode-tree explorer** `[4]` — depth-indented tree with case-insensitive
  filtering across method, decoder, content type, preview, and artifact name.
- **Graph viewer** `[5]` — interactive navigation of the decode graph: enter
  a node ID for full detail (parent, children, hashes, entropy, score,
  preview) and walk lineage; export the graph as JSON, DOT, or Mermaid via
  the core graph exporter (including intelligence annotations).
- **IOC browser** `[6]`, **Detection browser** `[7]` — filterable views of
  indicators and detections (with ATT&CK IDs).
- **Timeline explorer** `[8]` — normalized, sorted timeline events with
  filtering.
- **Evidence browser** `[9]` — DFIR evidence attached to the report: event
  and indicator counts, filterable evidence indicators, top pivots, and top
  links.
- **Correlation view** `[c]` — cross-case relationships, attribution hints,
  and campaign membership from the Phase 5 sections.
- **Search** `[/]` — case-insensitive search over every scalar field in
  every loaded report, ranked (exact > prefix > substring) with JSON-path
  locations.
- **Notes and tags** `[n]` — per-report tags, notes, and case status
  (open / in-progress / closed), plus workspace-level notes.
- **Export** `[e]` — IOC CSV and timeline CSV across all loaded reports, the
  active report's graph, and a portable investigation ZIP bundle
  (workspace + manifest + full report copies, `analyst-bundle-v1.0`).
- **Workspace persistence** `[s]`/`[o]` — save/open the investigation
  workspace (`analyst-workspace-v1.0`,
  `schemas/analyst-workspace-v1.0.schema.json`). Workspaces store report
  paths and annotations only — original reports remain unchanged.

## Typical session

```
titan workbench
  workbench> 1          # load ~/.titan_decoder/reports (or any directory)
  workbench> 2          # pick the case to focus
  workbench> /          # search "c2.example" across everything loaded
  workbench> 5          # walk the decode graph, export mermaid for the case notes
  workbench> n          # tag it, set status in-progress
  workbench> e          # export the investigation bundle
  workbench> s          # save the workspace
```
