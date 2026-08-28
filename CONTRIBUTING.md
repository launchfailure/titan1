# Contributing

Thanks for your interest in improving Titan Decoder. Contributions should preserve Titan's deterministic, bounded, offline-first, and explainable behavior.

## Before coding

- Open or reference an issue for substantial changes.
- Identify the owning subsystem, existing report contract, and security boundary.
- Keep changes **dependency-light** by default.
- Avoid combining unrelated refactors with behavior changes.
- Do not submit real incident evidence (logs, browser history DBs, reports) in issues or PRs.

## Development setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev,workbench-ui,desktop-ui,formats]'
pip install 'yara-python>=4.5.4'
python -m pytest --fail-on-skips
```

## Pull request expectations

- focused tests demonstrate the behavior;
- the full suite passes;
- new byte-processing code has malformed-input and resource-bound coverage;
- serialized output remains deterministic;
- public behavior and contracts are documented;
- no real incident data, credentials, or proprietary samples are committed;
- compatibility impact is explained.

## Commit hygiene

Use clear, focused commits that can be reviewed independently. Generated reports, extracted patch packages, virtual environments, caches, and local vault data should not be committed.

## Review checklist

Reviewers should check trust boundaries, output escaping, deterministic ordering, error handling, compatibility, and whether configuration defaults remain safe.
