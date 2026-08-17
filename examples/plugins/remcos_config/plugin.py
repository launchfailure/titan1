"""Extract high-value fields from a decrypted Remcos settings envelope."""

from titan_decoder.plugins.api import ConfigExtraction, ExtractorPlugin


class RemcosConfigExtractor(ExtractorPlugin):
    name = "Remcos Config"
    _MAX_INPUT = 1024 * 1024
    _DELIMITER = b"|\x1e\x1e\x1f|"

    @classmethod
    def _parse(cls, data):
        if not 32 <= len(data) <= cls._MAX_INPUT or cls._DELIMITER not in data:
            return None
        fields = data.split(cls._DELIMITER, 67)
        if len(fields) < 15:
            return None
        endpoint_record = fields[0]
        separator = next(
            (item for item in (b"|", b"\x1e", b"\xff\xff\xff\xff") if item in endpoint_record),
            None,
        )
        if separator is None:
            return None
        endpoint_part = endpoint_record.split(separator, 1)[0]
        pieces = endpoint_part.split(b":")
        if len(pieces) != 3:
            return None
        try:
            host = pieces[0].decode("ascii").encode("ascii").decode("idna").strip()
        except UnicodeError:
            return None
        try:
            port = int(pieces[1])
        except ValueError:
            return None
        if not host or not 1 <= port <= 65535:
            return None
        botnet = fields[1].decode("utf-8", errors="replace").strip("\x00 ")[:256]
        interval = fields[2].decode("ascii", errors="ignore").strip("\x00 ")[:32]
        mutex = fields[14].decode("utf-8", errors="replace").strip("\x00 ")[:256]
        # Boolean settings occupy stable positions and sharply reduce delimiter false positives.
        if any(fields[index] not in (b"\x00", b"\x01") for index in (3, 4, 5, 6)):
            return None
        values = {"host": host, "port": port}
        if botnet:
            values["botnet"] = botnet
        if interval.isdigit():
            values["connect_interval_seconds"] = int(interval)
        if mutex:
            values["mutex"] = mutex
        return values

    def can_extract(self, data, context=None):
        return self._parse(data) is not None

    def extract(self, data, context=None):
        values = self._parse(data)
        if values is None:
            return []
        return [
            ConfigExtraction(
                family="Remcos",
                confidence=0.98,
                values=values,
                c2=(f"tcp://{values['host']}:{values['port']}",),
                campaign_id=values.get("botnet"),
                metadata={"format": "decrypted-settings-v1"},
            )
        ]
