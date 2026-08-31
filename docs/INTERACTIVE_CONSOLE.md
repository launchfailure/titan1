# Interactive Console

The advanced `titan cli --interactive` command (or
`python -m titan_decoder.interactive`) opens a stdlib-only terminal
application suitable for local shells, SSH, and Codespaces. It is a pure
presentation layer over the existing engine — it does not duplicate
decoding, detection, correlation, or plugin logic.

## Screens

- **Dashboard** — session panel (engine version, profile, network mode,
  aggressive toggle) and system panel (decoder count, plugin count with
  load-error indicator, correlation database status, reports directory),
  rendered as responsive side-by-side boxes.
- **Analyze input** `[1]` — full recursive engine run with progress
  presentation, a concise analysis summary box (nodes, IOCs, detections,
  correlation hits, depth), elapsed time, the standard engine summary, and
  an optional JSON report save (defaults to
  `~/.titan_decoder/reports/latest.json`; `-` skips).
- **Decode with one decoder** `[2]` and **Decoder catalog** `[3]` — the
  existing single-decoder workflow and catalog listing.
- **Plugin manager** `[4]` — read-only Plugin SDK status over the same
  directory set the engine searches: manifest plugins with version and
  capabilities, single-file plugins, and per-plugin load errors.
- **Reports browser** `[5]` — the 20 most recent saved JSON reports; opening
  one renders its summary box and engine summary.
- **Settings** `[6]` — analysis profile (safe/fast/full), network mode
  (offline/online), aggressive auto-detect toggle, and the session reports
  directory.

## Behavior notes

- Offline mode (the default) wraps analysis in the network guard, exactly
  like `--offline` on the CLI.
- Plugin status shown on the dashboard is cached per session; the plugin
  manager screen refreshes it. Listing plugins loads their modules — the
  same trust model as running an analysis with plugins installed.
- All keyboard interaction is line-based numeric navigation; Ctrl+D or
  Ctrl+C ends the session cleanly.
- The classic minimal UI remains available in-process as
  `titan_decoder.interactive.InteractiveApp`; the enhanced console
  (`titan_decoder.ui.console.EnhancedInteractiveApp`) subclasses it.
