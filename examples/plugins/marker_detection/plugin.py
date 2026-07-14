"""Example detection plugin.

Demonstrates the Detection SDK: declared ``rule_ids`` (never using the
reserved ``TITAN-`` prefix), evidence-carrying :class:`DetectionFinding`
results, and the report/IOC inputs.
"""

from titan_decoder.plugins.api import DetectionFinding, DetectionPlugin

MARKER = "malware-marker"


class MarkerDetection(DetectionPlugin):
    @property
    def name(self):
        return "Example Marker"

    @property
    def rule_ids(self):
        return ("EXAMPLE-001",)

    def detect(self, report, iocs, context=None):
        matched_nodes = [
            node.get("id")
            for node in report.get("nodes") or []
            if MARKER in str(node.get("content_preview") or "").lower()
        ]
        if not matched_nodes:
            return []
        return [
            DetectionFinding(
                rule_id="EXAMPLE-001",
                name="Example Marker",
                description="Synthetic example marker found in decoded content",
                severity="medium",
                evidence=tuple({"node_id": node_id} for node_id in matched_nodes),
            )
        ]
