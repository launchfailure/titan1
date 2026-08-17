"""Extract selected fields from Cobalt Strike 3.x and 4.x Beacon configs."""

from titan_decoder.plugins.api import ConfigExtraction, ExtractorPlugin


class CobaltStrikeConfigExtractor(ExtractorPlugin):
    name = "Cobalt Strike Beacon Config"
    _MAX_INPUT = 16 * 1024 * 1024
    _CONFIG_SIZE = 4096
    _XOR_KEYS = (0x69, 0x2E)
    _START = b"\x00\x01\x00\x01\x00\x02"
    _FIELDS = {
        1: ("beacon_type", 1, 2),
        2: ("port", 1, 2),
        3: ("sleep_ms", 2, 4),
        5: ("jitter", 1, 2),
        8: ("c2_server", 3, 256),
        9: ("user_agent", 3, 128),
        10: ("http_post_uri", 3, 64),
        15: ("pipe_name", 3, 128),
        37: ("watermark", 2, 4),
        54: ("host_header", 3, 128),
    }

    @classmethod
    def _candidate(cls, data):
        if not 18 <= len(data) <= cls._MAX_INPUT:
            return None
        decoded_at = data.find(cls._START)
        if decoded_at >= 0:
            return data[decoded_at : decoded_at + cls._CONFIG_SIZE], "decoded", None
        for key in cls._XOR_KEYS:
            marker = bytes(value ^ key for value in cls._START)
            offset = data.find(marker)
            if offset >= 0:
                block = data[offset : offset + cls._CONFIG_SIZE]
                return bytes(value ^ key for value in block), "xor", key
        return None

    @classmethod
    def _parse(cls, data):
        candidate = cls._candidate(data)
        if candidate is None:
            return None
        block, encoding, xor_key = candidate
        values = {}
        for field_id, (label, data_type, length) in cls._FIELDS.items():
            header = bytes((0, field_id, 0, data_type)) + length.to_bytes(2, "big")
            offset = block.find(header)
            if offset < 0 or offset + 6 + length > len(block):
                continue
            raw = block[offset + 6 : offset + 6 + length]
            if data_type == 3:
                text = (
                    raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace").strip()
                )
                if text:
                    values[label] = text
            else:
                values[label] = int.from_bytes(raw, "big")
        # Endpoint and timing fields jointly make the short start marker specific.
        required = {"port", "sleep_ms", "c2_server"}
        if not required <= values.keys() or not 1 <= values["port"] <= 65535:
            return None
        if not 1 <= values["sleep_ms"] <= 86_400_000:
            return None
        return values, encoding, xor_key

    def can_extract(self, data, context=None):
        return self._parse(data) is not None

    def extract(self, data, context=None):
        parsed = self._parse(data)
        if parsed is None:
            return []
        values, encoding, xor_key = parsed
        server = values["c2_server"]
        port = values["port"]
        endpoint = server if "://" in server else f"tcp://{server}:{port}"
        metadata = {"format": "beacon-config-tlv", "encoding": encoding}
        if xor_key is not None:
            metadata["xor_key_hex"] = f"{xor_key:02x}"
        return [
            ConfigExtraction(
                family="Cobalt Strike Beacon",
                confidence=0.99,
                values=values,
                c2=(endpoint,),
                metadata=metadata,
            )
        ]
