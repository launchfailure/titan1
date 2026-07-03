# Plugin API

Titan exposes a **stable, versioned plugin API** so a third party can ship a
decoder or analyzer against a documented interface — without reading engine
internals — and have it keep working across engine releases.

Import only from `titan_decoder.plugins.api`. Everything there is covered by the
compatibility contract below.

## API version

The current API version is exported as `PLUGIN_API_VERSION` (currently `1.0`),
formatted `MAJOR.MINOR`.

- **MAJOR** bump = a breaking change to the base-class method signatures or
  semantics. Plugins built for an older MAJOR are **rejected** at load time.
- **MINOR** bump = an additive, backward-compatible extension. Older plugins
  keep working.

A plugin declares the API version it was built against with a module-level
`PLUGIN_API_VERSION`. The loader compares MAJOR versions and skips a plugin on a
breaking mismatch (logging a warning) rather than loading something incompatible.

## Writing a decoder

```python
from titan_decoder.plugins.api import PluginDecoder, PLUGIN_API_VERSION

PLUGIN_API_VERSION = PLUGIN_API_VERSION  # declare the API you built against


class Rot47Decoder(PluginDecoder):
    @property
    def name(self) -> str:
        return "ROT47"

    @property
    def priority(self) -> int:      # optional; higher = tried earlier
        return 0

    def can_decode(self, data: bytes) -> bool:
        return bool(data) and data[:1].isascii()

    def decode(self, data: bytes) -> tuple[bytes, bool]:
        out = bytes(
            (b - 33 + 47) % 94 + 33 if 33 <= b <= 126 else b for b in data
        )
        return out, out != data
```

Drop the file into a plugin directory (`~/.titan_decoder/plugins/`, the built-in
`titan_decoder/plugins/` dir, or any dir passed via config `plugin_dirs`). The
manager discovers `PluginDecoder`/`PluginAnalyzer` subclasses automatically.

## Writing an analyzer

```python
from titan_decoder.plugins.api import PluginAnalyzer, PLUGIN_API_VERSION

PLUGIN_API_VERSION = PLUGIN_API_VERSION


class MyContainerAnalyzer(PluginAnalyzer):
    @property
    def name(self) -> str:
        return "MyContainer"

    def can_analyze(self, data: bytes) -> bool:
        return data[:4] == b"MYC1"

    def analyze(self, data: bytes) -> list[tuple[str, bytes]]:
        # Return (artifact_name, content) pairs. The name becomes the node's
        # artifact_name and appears in its provenance record.
        return [("payload.bin", data[4:])]
```

## Contract every plugin must uphold

These are the same safety invariants the engine's built-ins are held to (and the
fuzz harness checks). A plugin that violates them can compromise the engine's
guarantees:

1. **Never raise uncaught.** `can_decode`/`can_analyze` and `decode`/`analyze`
   must return normally on *any* input, including malformed/hostile bytes.
   Signal failure with `(data, False)` (decoder) or `[]` (analyzer).
2. **Return the declared types.** Decoder: `tuple[bytes, bool]`. Analyzer:
   `list[tuple[str, bytes]]`.
3. **Bound your output.** Do not expand output without limit (respect a size
   cap if you decompress). The engine enforces its own caps, but a plugin that
   allocates gigabytes before returning defeats them.
4. **Terminate quickly.** No unbounded loops or catastrophic backtracking; a
   single call must finish well within the engine's per-decode timeout.

## Stability guarantee

Within a MAJOR version, the public names in `titan_decoder.plugins.api`
(`PluginDecoder`, `PluginAnalyzer`, `PLUGIN_API_VERSION`, `is_api_compatible`)
and the method signatures above will not change in a breaking way. Build against
`api`, declare your `PLUGIN_API_VERSION`, and pin the MAJOR you support.
