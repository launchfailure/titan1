"""Tests for the versioned plugin API contract.

A plugin written against the public API (titan_decoder.plugins.api) must load
and run without touching engine internals, and the loader must reject a plugin
that declares an incompatible MAJOR API version.
"""

from pathlib import Path

from titan_decoder.plugins import (
    PLUGIN_API_VERSION,
    PluginManager,
    is_api_compatible,
)


COMPATIBLE_PLUGIN = """
from titan_decoder.plugins.api import PluginDecoder, PLUGIN_API_VERSION

PLUGIN_API_VERSION = PLUGIN_API_VERSION


class ReverseDecoder(PluginDecoder):
    @property
    def name(self):
        return "ReversePlugin"

    def can_decode(self, data):
        return len(data) >= 4

    def decode(self, data):
        return data[::-1], True
"""

INCOMPATIBLE_PLUGIN = """
from titan_decoder.plugins.api import PluginDecoder

# Declares a future MAJOR the engine does not provide.
PLUGIN_API_VERSION = "999.0"


class FromTheFutureDecoder(PluginDecoder):
    @property
    def name(self):
        return "FromTheFuture"

    def can_decode(self, data):
        return True

    def decode(self, data):
        return data, False
"""


def test_is_api_compatible():
    assert is_api_compatible(PLUGIN_API_VERSION)
    major = PLUGIN_API_VERSION.split(".")[0]
    assert is_api_compatible(f"{major}.999")  # same major, newer minor
    assert not is_api_compatible("999.0")
    assert not is_api_compatible("garbage")


def test_compatible_plugin_loads_and_runs(tmp_path: Path):
    (tmp_path / "revplugin.py").write_text(COMPATIBLE_PLUGIN)
    mgr = PluginManager([tmp_path])
    mgr.load_plugins()
    names = [d.name for d in mgr.get_decoders()]
    assert "ReversePlugin" in names
    dec = next(d for d in mgr.get_decoders() if d.name == "ReversePlugin")
    out, ok = dec.decode(b"abcd")
    assert ok and out == b"dcba"


def test_incompatible_plugin_is_skipped(tmp_path: Path):
    (tmp_path / "future.py").write_text(INCOMPATIBLE_PLUGIN)
    mgr = PluginManager([tmp_path])
    mgr.load_plugins()
    names = [d.name for d in mgr.get_decoders()]
    assert "FromTheFuture" not in names


def test_plugin_info_reports_api_version(tmp_path: Path):
    mgr = PluginManager([tmp_path])
    mgr.load_plugins()
    info = mgr.get_plugin_info()
    assert info["api_version"] == PLUGIN_API_VERSION
