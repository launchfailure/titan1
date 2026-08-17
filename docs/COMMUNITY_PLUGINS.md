# Community plugin catalog

`registry/plugins-v1.json` is Titan's reviewable, offline catalog. It is data,
not an installer: listing it never downloads or executes code. Entries pin a
full Git commit, use an HTTPS source URL, declare a semantic plugin/API version,
capabilities, publisher, and license, and are validated by both the runtime
loader and `schemas/titan-plugin-catalog-v1.0.schema.json`.

List entries compatible with the installed Plugin API:

```console
titan-plugin-catalog registry/plugins-v1.json
```

The catalog starts with Titan's reference ROT47 package so the contribution
and compatibility path is executable end to end. Community additions should
submit a pull request that adds a pinned entry, demonstrates
`titan-decoder --plugin-validate`, includes positive and negative tests, and
passes the isolated-worker security checks. Catalog inclusion is not an
endorsement and does not replace source review.

Titan intentionally does not auto-install catalog entries. Analysts retrieve
and inspect the pinned source themselves, then configure its directory through
the normal Plugin API workflow. This keeps offline operation and explicit trust
decisions intact.
