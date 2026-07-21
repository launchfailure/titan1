# Titan Forensic Workbench — Integrated Build

This build advances the Phase 9.1 shell toward the approved visual design.

## Install and launch

```bash
python -m pip install -e '.[workbench-ui]'
titan-ui
```

The existing `titan-workbench-ui` command remains an equivalent alias.

## Terminal file drops

Titan accepts a single file or folder dropped anywhere in the workbench when
the terminal emulator represents the drop as a bracketed paste. The path is
placed in the evidence input and analysis starts immediately. Quoted paths,
`file://` URIs, native POSIX paths, and Windows drive paths pasted into a WSL
session are normalized before they are resolved.

The terminal emulator still owns the operating-system drop operation. If it
does not emit the path, click the drop zone and paste the path manually. A drop
is only auto-analyzed when it resolves to an existing local file or directory;
ordinary pasted text continues to be treated as evidence.

## Analysis outcomes

The Summary tab distinguishes fully interpreted content from incomplete work.
Reports carry an `analysis_outcome` with one of `decoded`, `analyzed`,
`partial_decode`, `unrecognized`, `limited`, or `empty_input`. Partial and
unrecognized outcomes identify opaque terminal nodes and explicitly warn that
the absence of indicators is not a benign verdict. The Decode Tree displays
decoder scores, low-confidence labels, and the reason processing stopped.

The Summary begins with the assurance verdict and completed-control count.
Assurance blockers are shown in the findings card. The workbench automatically
runs Titan's offline static suite; VM and provenance controls consume the
hash-bound provider attestations configured in `~/.titan_decoder/config.json`.

## Implemented

- permanent left, center, and right columns;
- compact custom header and status bar with live session state;
- independently scrollable navigation, investigation, results, and decoder areas;
- dense quick-start rows in place of oversized action buttons;
- investigation input and file-path workspace;
- always-visible decoder browser and details panel;
- live decoder inventory from Titan;
- session, system, engine, and resource cards;
- analysis result tabs;
- findings, detections, strings, IOCs, decode tree, and hex views;
- recursive analysis through `TitanEngine`;
- manual decoder execution through the existing decoder registry;
- report loading and output saving;
- plugin, correlation, report, and local system status;
- session settings for profile, offline mode, and aggressive detection;
- detailed dark forensic theme.

## Safety

The new UI is a presentation layer. It does not replace or duplicate Titan's
analysis logic, and the existing `titan` command remains unchanged.


## Completion recovery update

The recovered build is now complete for the planned integrated scope:

- Correlation and timeline routes render live data from the active Titan report.
- Local AI Analyst questions run through Titan's citation-enforced deterministic AnalystEngine.
- Directory paths execute as a sorted multi-file queue and save one local report per file.
- Dynamic center-panel replacement is stable across repeated navigation.
- Importing lightweight workbench modules no longer requires Textual.
- Long pasted payloads are treated as evidence even when they exceed filesystem
  filename limits.
- Batch report names include deterministic path/content identities, preventing
  duplicate basenames from overwriting evidence.
- Evidence-derived text is escaped before Textual markup rendering, and malformed
  nested report values are ignored instead of crashing result views.

## Textual 1.0 dynamic-view hotfix

Every dynamic center-panel replacement, including analysis and decoder result
refreshes, awaits both widget removal and mounting. This prevents
`DuplicateIds: dynamic-view` during navigation and normal analysis workflows.
