"""Example report plugin.

Demonstrates the Report SDK: a JSON-serializable :class:`ReportSection`
rendered into the JSON report and Markdown/HTML case reports.
"""

from titan_decoder.plugins.api import ReportPlugin, ReportSection


class SummaryReport(ReportPlugin):
    @property
    def name(self):
        return "Example Summary"

    def build_sections(self, report, context=None):
        return [
            ReportSection(
                section_id="example_summary",
                title="Example Plugin Summary",
                content={
                    "node_count": report.get("node_count", 0),
                    "detection_count": len(report.get("detections") or []),
                },
                order=900,
                formats=("json", "markdown", "html"),
            )
        ]
