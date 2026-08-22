# Titan Forensic Workbench — Integrated Build

Titan provides a native PySide6 desktop workbench and a Textual terminal
workbench. Both use the same deterministic engine and report model, but they are
different interfaces with different optional dependencies.

## Install and launch

### Native desktop workbench

```bash
python -m pip install -e '.[desktop-ui,formats]'
titan gui
```

On Windows, use the two-environment setup and `Titan-Windows.cmd` launcher
documented in [WINDOWS_DESKTOP_UI.md](WINDOWS_DESKTOP_UI.md). That build receives
native File Explorer drag-and-drop events and delegates analysis to Debian
through WSL.

### Textual terminal workbench

```bash
python -m pip install -e '.[workbench-ui]'
titan tui
```

`titan tui` opens the terminal interface; `titan` and `titan gui` open the
native desktop application.

## Textual terminal file drops

Titan accepts a single file or folder dropped anywhere in the workbench when
the terminal emulator represents the drop as a bracketed paste. The path is
placed in the evidence input and analysis starts immediately. Quoted paths,
`file://` URIs, native POSIX paths, and Windows drive paths pasted into a WSL
session are normalized before they are resolved.

The terminal emulator still owns the operating-system drop operation. If it
does not emit the path, click the drop zone and paste the path manually. A drop
is only auto-analyzed when it resolves to an existing local file or directory;
ordinary pasted text continues to be treated as evidence.

For native Windows Explorer drag-and-drop and its troubleshooting steps, use
the [Windows Desktop Workbench guide](WINDOWS_DESKTOP_UI.md).

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

## Shared workbench capabilities

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

The native desktop additionally provides desktop dialogs, native Explorer file
drops, application artwork, and the Debian analysis bridge. Some navigation and
presentation details differ between the PySide6 and Textual front ends.

## Safety

The workbench interfaces are presentation layers. They do not replace or
duplicate Titan's analysis logic, and the existing `titan` command remains
unchanged. WSL is not a VM isolation boundary; do not execute unknown or
recovered payloads merely because the workbench can inspect them.


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
