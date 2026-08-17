"""Real-format fixtures and near misses for Titan's seed config extractors."""

from pathlib import Path

import pytest

from titan_decoder.plugins import PluginManager


PLUGINS = Path(__file__).resolve().parents[1] / "examples" / "plugins"


def _field(field_id: int, kind: int, size: int, value: bytes | int) -> bytes:
    raw = (
        value.to_bytes(size, "big")
        if isinstance(value, int)
        else value.ljust(size, b"\x00")
    )
    return bytes((0, field_id, 0, kind)) + size.to_bytes(2, "big") + raw


def _cobalt_config(*, xor_key: int | None = None) -> bytes:
    decoded = b"".join(
        (
            _field(1, 1, 2, 8),
            _field(2, 1, 2, 443),
            _field(3, 2, 4, 60_000),
            _field(5, 1, 2, 20),
            _field(8, 3, 256, b"team.example"),
            _field(9, 3, 128, b"Mozilla/5.0"),
            _field(10, 3, 64, b"/submit.php"),
            _field(37, 2, 4, 0x10203040),
        )
    ).ljust(4096, b"\x00")
    if xor_key is None:
        return decoded
    return bytes(value ^ xor_key for value in decoded)


def _extractor(plugin: str):
    manager = PluginManager([PLUGINS / plugin])
    manager.load_plugins()
    assert manager.errors == []
    return manager.extractors[0]


@pytest.mark.parametrize("xor_key", [None, 0x69, 0x2E])
def test_cobalt_strike_decoded_and_xor_variants_run_isolated(xor_key):
    extractor = _extractor("cobalt_strike_config")
    results = extractor.extract(b"prefix" + _cobalt_config(xor_key=xor_key))
    assert len(results) == 1
    result = results[0]
    assert result.family == "Cobalt Strike Beacon"
    assert result.values["sleep_ms"] == 60_000
    assert result.values["jitter"] == 20
    assert result.values["watermark"] == 0x10203040
    assert result.c2 == ("tcp://team.example:443",)
    assert result.metadata["encoding"] == ("decoded" if xor_key is None else "xor")


def test_cobalt_strike_rejects_marker_only_and_invalid_timing():
    extractor = _extractor("cobalt_strike_config")
    assert not extractor.can_extract(b"\x00\x01\x00\x01\x00\x02" + b"noise" * 20)
    invalid = _cobalt_config().replace(
        (60_000).to_bytes(4, "big"), b"\x00\x00\x00\x00", 1
    )
    assert extractor.extract(invalid) == []


def _remcos_config() -> bytes:
    fields = [b"c2.example:2404:secret\x1eTLS", b"blue-team", b"10"]
    fields.extend((b"\x01", b"\x01", b"\x00", b"\x00"))
    fields.extend(b"unused" for _ in range(7))
    fields.append(b"Global\\Remcos-Mutex")
    return b"|\x1e\x1e\x1f|".join(fields)


def test_remcos_decrypted_settings_extract_high_value_fields():
    result = _extractor("remcos_config").extract(_remcos_config())[0]
    assert result.family == "Remcos"
    assert result.c2 == ("tcp://c2.example:2404",)
    assert result.campaign_id == "blue-team"
    assert result.values["connect_interval_seconds"] == 10
    assert result.values["mutex"] == "Global\\Remcos-Mutex"


def test_remcos_rejects_short_delimited_text_and_bad_boolean_layout():
    extractor = _extractor("remcos_config")
    assert extractor.extract(b"host:80:key" + extractor._DELIMITER + b"noise") == []
    invalid = _remcos_config().replace(b"\x01", b"maybe", 1)
    assert not extractor.can_extract(invalid)
