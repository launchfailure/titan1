"""Example decoder plugin: ROT47.

Demonstrates the Decoder SDK: typed :class:`DecodeResult`, an optional
context argument, and priority ordering. ``can_decode``/``decode`` never
raise and always bound their output (same size as input).
"""

from titan_decoder.plugins.api import DecodeResult, DecoderPlugin


class Rot47Decoder(DecoderPlugin):
    priority = 10

    @property
    def name(self):
        return "ROT47"

    def can_decode(self, data, context=None):
        return bool(data) and all(b in b"\t\r\n" or 32 <= b <= 126 for b in data)

    def decode(self, data, context=None):
        out = bytes(((b - 33 + 47) % 94) + 33 if 33 <= b <= 126 else b for b in data)
        return DecodeResult(out, out != data, {"algorithm": "ROT47"})
