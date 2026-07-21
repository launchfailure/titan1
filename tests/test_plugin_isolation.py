import json
import os
from pathlib import Path

import pytest

from titan_decoder.plugins import PluginContext, PluginManager


def _plugin(
    root: Path,
    body: str,
    *,
    permissions: list[str] | None = None,
    plugin_id: str = "test.isolated",
) -> Path:
    directory = root / plugin_id.replace(".", "_")
    directory.mkdir()
    (directory / "plugin.py").write_text(body, encoding="utf-8")
    (directory / "titan-plugin.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "id": plugin_id,
                "name": "Isolation Test",
                "version": "1.0.0",
                "api_version": "1.1.0",
                "entry_point": "plugin:Example",
                "capabilities": ["decoder"],
                "permissions": permissions or [],
            }
        ),
        encoding="utf-8",
    )
    return directory


def test_manifest_plugin_executes_in_a_different_process(tmp_path):
    _plugin(
        tmp_path,
        """import os
from titan_decoder.plugins.api import DecodeResult, DecoderPlugin
class Example(DecoderPlugin):
    name = 'Isolated'
    def can_decode(self, data, context=None): return True
    def decode(self, data, context=None):
        return DecodeResult(data[::-1], True, {'pid': os.getpid(), 'config': dict(context.config)})
""",
    )
    manager = PluginManager([tmp_path])
    manager.load_plugins()
    decoder = manager.decoders[0]

    result = decoder.decode(
        b"abcd", PluginContext(config={"secret": "not disclosed"})
    )

    assert result.data == b"dcba"
    assert result.metadata["pid"] != os.getpid()
    assert result.metadata["config"] == {}
    assert manager.get_plugin_info()["execution_mode"] == "isolated"


def test_configuration_permission_controls_context_disclosure(tmp_path):
    _plugin(
        tmp_path,
        """from titan_decoder.plugins.api import DecodeResult, DecoderPlugin
class Example(DecoderPlugin):
    name = 'Configured'
    def can_decode(self, data, context=None): return True
    def decode(self, data, context=None):
        return DecodeResult(data, True, {'config': dict(context.config)})
""",
        permissions=["configuration"],
    )
    manager = PluginManager([tmp_path])
    manager.load_plugins()

    result = manager.decoders[0].decode(
        b"data", PluginContext(config={"allowed": "value"})
    )

    assert result.metadata["config"] == {"allowed": "value"}


def test_network_permission_plugin_is_refused_offline(tmp_path):
    _plugin(
        tmp_path,
        """from titan_decoder.plugins.api import DecoderPlugin
class Example(DecoderPlugin):
    name = 'Networked'
    def can_decode(self, data, context=None): return False
    def decode(self, data, context=None): return data, False
""",
        permissions=["network"],
    )
    manager = PluginManager([tmp_path], offline=True)
    manager.load_plugins()

    assert manager.decoders == []
    assert "network access in offline mode" in manager.errors[0]["error"]


def test_isolated_plugin_call_is_terminated_at_timeout(tmp_path):
    _plugin(
        tmp_path,
        """import time
from titan_decoder.plugins.api import DecoderPlugin
class Example(DecoderPlugin):
    name = 'Slow'
    def can_decode(self, data, context=None):
        time.sleep(5)
        return True
    def decode(self, data, context=None): return data, False
""",
    )
    manager = PluginManager([tmp_path], timeout_seconds=1)
    manager.load_plugins()

    with pytest.raises(TimeoutError, match="exceeded the 1s timeout"):
        manager.decoders[0].can_decode(b"data")
