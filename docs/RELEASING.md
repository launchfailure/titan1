# Releasing Titan Decoder (Preview + PyPI)

This doc is a practical checklist for:

- A **preview/beta** release shared via **GitHub only** (recommended for early community feedback)
- A later **PyPI** release (optional; do this when you want frictionless installs)

If you’re not publishing to PyPI yet, you still want a lightweight, repeatable way to point people to a specific snapshot (a tag/release). That’s what the “Preview (GitHub-only)” section is for.

## Preview (GitHub-only) — recommended for feedback

1. Pick a preview tag name

Examples:

- `v2.0.0-preview.1`
- `v2.0.0-beta.1`

2. (Optional) bump version if you want tags and `__version__` to match

Edit [titan_decoder/__init__.py](titan_decoder/__init__.py):

- `__version__ = "2.0.0"` (or `2.0.0b1` if you prefer)

3. Run tests

```bash
python -m pytest -q
```

Doc sync (recommended when behavior/options changed):

- Update examples and option descriptions in:
  - [README.md](README.md)
  - [docs/USAGE.md](docs/USAGE.md)
  - [docs/ANNOUNCEMENT.md](docs/ANNOUNCEMENT.md)

If the JSON report contract changed (new fields/sections), also update:

- [docs/report.schema.json](docs/report.schema.json)

4. Create and push the tag

```bash
git tag -a v2.0.0-preview.1 -m "Titan Decoder preview v2.0.0-preview.1"
git push origin v2.0.0-preview.1
```

5. Create a GitHub Release

On GitHub → Releases → “Draft a new release”:

- Tag: `v2.0.0-preview.1`
- Title: `Titan Decoder v2.0.0-preview.1 (Preview)`
- In the body, be explicit:
  - “Preview / feedback requested”
  - what you want feedback on (IOCs, false positives, decoders, UX)
  - that it’s not a hardened production tool yet

That’s enough to share widely and get feedback.

## Automated release via GitHub Actions (recommended)

The repo ships a release pipeline in [.github/workflows/release.yml](../.github/workflows/release.yml)
that runs automatically when you **push a `v*` tag**. You do not need to build,
sign, or upload anything by hand. On a tag push it:

1. Verifies the committed SBOM (`docs/sbom.cdx.json`) matches a fresh regeneration.
2. Does a **reproducible build** (`SOURCE_DATE_EPOCH` pinned to the tagged commit;
   the sdist tarball is normalized by `tools/repack_sdist.py`).
3. **Signs** the `.whl` and `.tar.gz` with Sigstore (keyless, via OIDC).
4. Uploads the wheel, sdist, signatures, and SBOM as **GitHub Release** assets.
5. **Optionally publishes to PyPI** — only if you have opted in (see below).

So the everyday release is just:

```bash
# 1. Bump the version
#    edit titan_decoder/__init__.py  ->  __version__ = "X.Y.Z"
# 2. Run tests + update docs/CHANGELOG as needed
python -m pytest -q
# 3. Commit, then tag and push the tag
git tag -a vX.Y.Z -m "Titan Decoder vX.Y.Z"
git push origin vX.Y.Z
```

### Enabling automated PyPI publishing (one-time, opt-in)

The `publish-pypi` job is **disabled by default** so it can never break a
release. It uses PyPI **Trusted Publishing** (OpenID Connect) — no API token is
stored anywhere. To turn it on:

1. **Configure a Trusted Publisher on PyPI.** On the `titan-decoder` project page
   (or, for the very first upload, as a
   [pending publisher](https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/)):
   PyPI → *Manage* → *Publishing* → *Add a new pending/trusted publisher* →
   *GitHub Actions*, and enter:
   - **Owner:** `pragmaconflux`
   - **Repository:** `titan1`
   - **Workflow name:** `release.yml`
   - **Environment name:** `pypi`
2. **Create the `pypi` GitHub Environment** (optional but recommended for a
   manual approval gate): GitHub → *Settings* → *Environments* → *New environment*
   → name it `pypi`. The workflow already targets `environment: pypi`.
3. **Set the opt-in variable.** GitHub → *Settings* → *Secrets and variables* →
   *Actions* → *Variables* → *New repository variable*:
   - **Name:** `PUBLISH_TO_PYPI`
   - **Value:** `true`

After that, every `v*` tag push builds, signs, creates the GitHub Release, **and**
publishes to PyPI, so users can `pip install titan-decoder`.

To pause PyPI publishing again, set `PUBLISH_TO_PYPI` to anything other than
`true` (or delete the variable). GitHub-only releases keep working unchanged.

> The manual `twine` / API-token workflow below is the fallback (handy for a
> one-off **TestPyPI** dry run). With Trusted Publishing enabled you do **not**
> need an API token or `~/.pypirc` for real releases.

## One-time setup

> **Manual path (fallback).** The steps in this section and the "PyPI release
> checklist" below cover the token-based `twine` upload. If you enabled the
> automated Trusted Publishing pipeline above, you can skip the API token and
> `~/.pypirc` for real releases — keep this only for TestPyPI dry runs.

1. Create accounts
- PyPI: https://pypi.org/
- (Recommended) TestPyPI: https://test.pypi.org/

2. Create an API token on PyPI (Account settings → API tokens)

3. Configure `~/.pypirc` (optional but convenient)

Example:

```ini
[pypi]
  username = __token__
  password = pypi-<YOUR_TOKEN>

[testpypi]
  repository = https://test.pypi.org/legacy/
  username = __token__
  password = pypi-<YOUR_TEST_TOKEN>
```

## PyPI release checklist (optional)

### 1) Pick the new version

Edit [titan_decoder/__init__.py](titan_decoder/__init__.py) and bump:

- `__version__ = "X.Y.Z"`

Use SemVer:
- Patch: bug fixes
- Minor: new features
- Major: breaking changes

### 2) Run tests locally

```bash
python -m pytest -q
```

### 3) Build distributions

Install build tooling:

```bash
python -m pip install -U build twine
```

Build:

```bash
python -m build
```

This creates:
- `dist/*.whl`
- `dist/*.tar.gz`

### 4) Check the package

```bash
twine check dist/*
```

### 5) (Recommended) Upload to TestPyPI first

```bash
twine upload -r testpypi dist/*
```

Test install from TestPyPI:

```bash
python -m pip install -i https://test.pypi.org/simple/ titan-decoder
```

### 6) Upload to PyPI

```bash
twine upload dist/*
```

### 7) Tag the release in git (recommended)

```bash
git tag -a vX.Y.Z -m "Titan Decoder vX.Y.Z"
git push origin vX.Y.Z
```

### 8) Create a GitHub Release

On GitHub → Releases → “Draft a new release”, pick the `vX.Y.Z` tag, paste highlights.

## Quick “release notes” template

- Added: …
- Fixed: …
- Changed: …
- Docs: …

## Common pitfalls

- If `pip install titan-decoder` works locally but not for users: verify you uploaded both sdist + wheel.
- If metadata looks wrong on PyPI: check the `[project]` table in `pyproject.toml` and rerun `python -m build`.
- If a dependency is missing: add it to `install_requires` (core) or the `enrichment` extra.
