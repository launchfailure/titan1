# Titan Forensic Workbench — Integrated Build

This build advances the Phase 9.1 shell toward the approved visual design.

## Implemented

- permanent left, center, and right columns;
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

## Textual 1.0 dynamic-view hotfix

Dynamic center-panel replacement now awaits both widget removal and mounting.
This prevents `DuplicateIds: dynamic-view` when navigating between Reports,
Plugins, Settings, Correlation, Timeline, and Analyst views.
