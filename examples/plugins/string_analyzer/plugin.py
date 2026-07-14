"""Example analyzer plugin: printable-string extraction.

Demonstrates the Analyzer SDK: typed :class:`AnalysisArtifact` results and
honoring the context's output bound.
"""

import re

from titan_decoder.plugins.api import AnalysisArtifact, AnalyzerPlugin


class StringsAnalyzer(AnalyzerPlugin):
    @property
    def name(self):
        return "PrintableStrings"

    def can_analyze(self, data, context=None):
        # Only binary data with embedded strings: extracting "strings" from
        # already-printable text would just duplicate the node and shadow
        # decoders that could act on it.
        if len(data) < 4:
            return False
        has_binary = any(b < 9 or (13 < b < 32) or b > 126 for b in data)
        return has_binary and re.search(rb"[ -~]{4,}", data) is not None

    def analyze(self, data, context=None):
        limit = context.max_output_bytes if context else 1024 * 1024
        parts = re.findall(rb"[ -~]{4,}", data)
        content = b"\n".join(parts)[:limit]
        if not content:
            return []
        return [AnalysisArtifact("strings.txt", content, {"count": len(parts)})]
