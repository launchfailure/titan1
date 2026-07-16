# Titan Forensic Workbench — Integrated Build

This build advances the Phase 9.1 shell toward the approved visual design.

## Install and launch

```bash
python -m pip install -e '.[workbench-ui]'
titan-ui
```

The existing `titan-workbench-ui` command remains an equivalent alias.

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
