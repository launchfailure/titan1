"""Example malware-configuration extractor for a synthetic beacon format."""

from titan_decoder.plugins.api import ConfigExtraction, ExtractorPlugin


class TitanBeaconConfigExtractor(ExtractorPlugin):
    name = "Titan Beacon Config"
    _MARKER = b"TITAN-BEACON|"

    def can_extract(self, data, context=None):
        return data.startswith(self._MARKER) and len(data) <= 64 * 1024

    def extract(self, data, context=None):
        if not self.can_extract(data, context):
            return []
        values = {}
        for field in data[len(self._MARKER) :].split(b"|")[:32]:
            key, separator, value = field.partition(b"=")
            if not separator:
                continue
            label = key.decode("ascii", errors="ignore").strip().lower()[:64]
            text = value.decode("utf-8", errors="replace").strip()[:4096]
            if label and text:
                values[label] = text
        c2 = (values["c2"],) if "c2" in values else ()
        keys = (values["key"],) if "key" in values else ()
        return [
            ConfigExtraction(
                family="TitanBeacon",
                confidence=1.0,
                values=values,
                c2=c2,
                keys=keys,
                campaign_id=values.get("campaign"),
                metadata={"format": "synthetic-example-v1"},
            )
        ]
