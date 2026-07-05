"""Stable, versioned public plugin API for Titan.

Third-party decoders and analyzers should import **only** from this module. It
is the compatibility surface: everything here is covered by the
``PLUGIN_API_VERSION`` contract (see docs/PLUGIN_API.md), so a plugin written
against it keeps working across engine releases with the same MAJOR version,
without depending on engine internals.

Example plugin (``myplugin.py`` dropped in a plugin dir)::

    from titan_decoder.plugins.api import PluginDecoder, PLUGIN_API_VERSION

    PLUGIN_API_VERSION = PLUGIN_API_VERSION  # declare the API you built against

    class Rot47Decoder(PluginDecoder):
        @property
        def name(self):
            return "ROT47"

        def can_decode(self, data):
            return data[:1].isascii()

        def decode(self, data):
            out = bytes((b - 33 + 47) % 94 + 33 if 33 <= b <= 126 else b
                        for b in data)
            return out, out != data

Contract every plugin must uphold (enforced by the fuzz invariants):
``can_decode``/``can_analyze`` and ``decode``/``analyze`` must never raise,
must return the declared types, must bound their output, and must terminate
quickly on any input, including hostile bytes.
"""

from __future__ import annotations

from . import (
    PLUGIN_API_VERSION,
    PluginAnalyzer,
    PluginDecoder,
    is_api_compatible,
)

__all__ = [
    "PLUGIN_API_VERSION",
    "PluginDecoder",
    "PluginAnalyzer",
    "is_api_compatible",
]
