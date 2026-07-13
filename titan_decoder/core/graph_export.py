"""
Graph visualization and export for Titan Decoder Engine.

Exports deterministic analysis graphs as JSON, Graphviz DOT, and Mermaid.
When a completed Intelligence Layer object is supplied, graph-level metadata
and node-level priority annotations are added without changing the underlying
analysis tree.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Mapping, Sequence


class GraphExporter:
    """Export analysis graphs in JSON, DOT, and Mermaid formats."""

    PRIORITY_CLASSES = (
        (81, "critical"),
        (61, "high"),
        (36, "medium"),
        (16, "low"),
        (0, "none"),
    )

    PRIORITY_COLORS = {
        "critical": "#ffb3b3",
        "high": "#ffd6a5",
        "medium": "#fff3b0",
        "low": "#d9f2d9",
        "none": "#f0f8ff",
    }

    def __init__(
        self,
        nodes: List[Dict[str, Any]],
        intelligence: Mapping[str, Any] | None = None,
    ):
        self.nodes = nodes
        self.node_map = {node["id"]: node for node in nodes}
        self.intelligence = dict(intelligence or {})
        self._artifact_annotations = self._build_artifact_annotations()

    def to_json(self, include_metadata: bool = True) -> str:
        """Export graph as JSON.

        Existing consumers continue to receive ``nodes`` and ``edges``.
        Intelligence-aware consumers additionally receive graph metadata and
        per-node ``intelligence`` annotations.
        """
        graph_nodes = [self._annotated_node(node) for node in self.nodes]
        graph_data: Dict[str, Any] = {
            "nodes": graph_nodes,
            "edges": self._build_edges(),
        }

        if include_metadata:
            metadata: Dict[str, Any] = {
                "total_nodes": len(self.nodes),
                "max_depth": max((n.get("depth", 0) for n in self.nodes), default=0),
                "node_types": self._count_node_types(),
            }
            summary = self._intelligence_summary()
            if summary:
                metadata["intelligence"] = summary
            graph_data["metadata"] = metadata

        return json.dumps(graph_data, indent=2, default=str)

    def to_dot(self, title: str = "Titan Analysis Graph") -> str:
        """Export graph as Graphviz DOT with optional Intelligence annotations."""
        safe_title = self._dot_escape(title)
        lines = [f'digraph "{safe_title}" {{']
        lines.append("  rankdir=TB;")
        lines.append('  graph [fontname="Helvetica"];')
        lines.append('  node [shape=box, style="filled,rounded", fontname="Helvetica"];')
        lines.append('  edge [fontname="Helvetica"];')

        summary = self._intelligence_summary()
        if summary:
            label = (
                f"Classification: {summary['classification']}\\n"
                f"Intelligence: {summary['score']}/100\\n"
                f"Confidence: {summary['confidence_percent']}%"
            )
            lines.append(
                '  labelloc="t"; '
                f'label="{self._dot_escape(title)}\\n{self._dot_escape(label)}";'
            )
            lines.extend(self._dot_legend())

        for node in self.nodes:
            node_id = self._dot_id(node["id"])
            method = node.get("method", "UNKNOWN")
            score = self._safe_float(node.get("decode_score"))
            content_type = node.get("content_type", "Unknown")
            length = node.get("decoded_length", node.get("source_length", 0))
            annotation = self._artifact_annotations.get(node["id"])

            color = self._get_node_color(
                content_type,
                score,
                bool(node.get("pruned", False)),
                annotation,
            )
            label_parts = [
                str(method),
                f"{node.get('id')}: {content_type}",
                f"{length} bytes",
                f"Decode score: {score:.3f}",
            ]
            attrs = [f'label="{self._dot_escape(chr(10).join(label_parts)).replace(chr(10), r"\n")}"', f'fillcolor="{color}"']

            if annotation:
                reasons = ", ".join(annotation.get("reasons") or [])
                annotated_label = (
                    "\n".join(label_parts)
                    + f"\nPriority: {annotation['priority'].upper()}"
                    + f" ({annotation['score']}/100)"
                    + (f"\n{reasons}" if reasons else "")
                )
                attrs[0] = (
                    f'label="{self._dot_escape(annotated_label).replace(chr(10), r"\n")}"'
                )
                attrs.append('penwidth="2.5"')

            lines.append(f"  {node_id} [{', '.join(attrs)}];")

        for edge in self._build_edges():
            source = self._dot_id(edge["source"])
            target = self._dot_id(edge["target"])
            label = self._dot_escape(edge.get("label", ""))
            style = "dashed" if edge.get("type") == "pruned" else "solid"
            lines.append(
                f'  {source} -> {target} [label="{label}", style="{style}"];'
            )

        lines.append("}")
        return "\n".join(lines)

    def to_mermaid(self, title: str = "Titan Analysis Flow") -> str:
        """Export graph as Mermaid flowchart with optional Intelligence annotations."""
        lines = ["---", f"title: {self._mermaid_text(title)}", "---", "flowchart TD"]

        summary = self._intelligence_summary()
        if summary:
            summary_label = (
                f"Intelligence Assessment<br/>"
                f"{summary['classification']} · {summary['score']}/100 · "
                f"{summary['confidence_percent']}%"
            )
            lines.append(f'    intelligence_summary["{summary_label}"]')
            lines.append("    class intelligence_summary titanSummary")

        for node in self.nodes:
            node_id = self._mermaid_id(node["id"])
            method = self._mermaid_text(node.get("method", "UNKNOWN"))
            content_type = self._mermaid_text(node.get("content_type", "Unknown"))
            score = self._safe_float(node.get("decode_score"))
            annotation = self._artifact_annotations.get(node["id"])

            label = f"{method}<br/>{content_type}<br/>Decode: {score:.3f}"
            if annotation:
                reasons = ", ".join(annotation.get("reasons") or [])
                label += (
                    f"<br/>Priority: {annotation['priority'].upper()} "
                    f"({annotation['score']}/100)"
                )
                if reasons:
                    label += f"<br/>{self._mermaid_text(reasons)}"

            open_b, close_b = self._get_mermaid_brackets(
                content_type,
                score,
                bool(node.get("pruned", False)),
            )
            lines.append(f"    {node_id}{open_b}{label}{close_b}")
            if annotation:
                lines.append(f"    class {node_id} titan{annotation['priority'].title()}")

        for edge in self._build_edges():
            source = self._mermaid_id(edge["source"])
            target = self._mermaid_id(edge["target"])
            label = self._mermaid_text(edge.get("label", ""))
            link_type = "-.->" if edge.get("type") == "pruned" else "-->"
            if label:
                lines.append(f"    {source} {link_type}|{label}| {target}")
            else:
                lines.append(f"    {source} {link_type} {target}")

        if summary:
            lines.extend(
                [
                    "    classDef titanSummary fill:#e8eefc,stroke:#4c6ef5,stroke-width:2px;",
                    "    classDef titanCritical fill:#ffb3b3,stroke:#c92a2a,stroke-width:3px;",
                    "    classDef titanHigh fill:#ffd6a5,stroke:#e67700,stroke-width:3px;",
                    "    classDef titanMedium fill:#fff3b0,stroke:#f08c00,stroke-width:2px;",
                    "    classDef titanLow fill:#d9f2d9,stroke:#2b8a3e,stroke-width:2px;",
                    "    classDef titanNone fill:#f0f8ff,stroke:#748ffc;",
                ]
            )

        return "\n".join(lines)

    def save_json(self, filepath: Path, include_metadata: bool = True) -> None:
        filepath.write_text(self.to_json(include_metadata), encoding="utf-8")

    def save_dot(self, filepath: Path, title: str = "Titan Analysis Graph") -> None:
        filepath.write_text(self.to_dot(title), encoding="utf-8")

    def save_mermaid(self, filepath: Path, title: str = "Titan Analysis Flow") -> None:
        filepath.write_text(self.to_mermaid(title), encoding="utf-8")

    def _annotated_node(self, node: Mapping[str, Any]) -> Dict[str, Any]:
        result = dict(node)
        annotation = self._artifact_annotations.get(node.get("id"))
        if annotation:
            result["intelligence"] = dict(annotation)
        return result

    def _build_artifact_annotations(self) -> Dict[Any, Dict[str, Any]]:
        annotations: Dict[Any, Dict[str, Any]] = {}
        artifacts = self.intelligence.get("top_artifacts") or []
        if not isinstance(artifacts, Sequence) or isinstance(artifacts, (str, bytes)):
            return annotations

        for rank, artifact in enumerate(artifacts[:5], start=1):
            if not isinstance(artifact, Mapping):
                continue
            node_id = artifact.get("node_id")
            if node_id not in self.node_map:
                continue
            artifact_score = self._safe_int(artifact.get("score"))
            annotations[node_id] = {
                "rank": rank,
                "score": artifact_score,
                "priority": self._priority_for_score(artifact_score),
                "reasons": [
                    str(reason) for reason in (artifact.get("reasons") or [])
                ],
                "artifact_name": artifact.get("artifact_name"),
            }
        return annotations

    def _intelligence_summary(self) -> Dict[str, Any]:
        if not self.intelligence:
            return {}
        score = self._safe_int(self.intelligence.get("intelligence_score"))
        confidence = self._safe_float(self.intelligence.get("confidence"))
        return {
            "version": self.intelligence.get("version"),
            "classification": self.intelligence.get("classification") or "UNKNOWN",
            "score": score,
            "confidence": confidence,
            "confidence_percent": round(confidence * 100),
            "recommendation": self.intelligence.get("recommendation"),
            "signal_codes": [
                str(signal.get("code"))
                for signal in (self.intelligence.get("signals") or [])
                if isinstance(signal, Mapping) and signal.get("code")
            ],
            "annotated_node_count": len(self._artifact_annotations),
        }

    def _dot_legend(self) -> List[str]:
        lines = ['  subgraph cluster_titan_legend {', '    label="Intelligence priority";']
        lines.append('    style="rounded,dashed";')
        for priority in ("critical", "high", "medium", "low"):
            color = self.PRIORITY_COLORS[priority]
            lines.append(
                f'    legend_{priority} [label="{priority.title()}", fillcolor="{color}", shape=box];'
            )
        lines.append("  }")
        return lines

    def _build_edges(self) -> List[Dict[str, Any]]:
        edges = []
        for node in self.nodes:
            parent_id = node.get("parent")
            if parent_id is not None:
                edge_type = "pruned" if node.get("pruned", False) else "decoded"
                edges.append(
                    {
                        "source": parent_id,
                        "target": node["id"],
                        "label": node.get("decoder_used", ""),
                        "type": edge_type,
                    }
                )
        return edges

    def _count_node_types(self) -> Dict[str, int]:
        types: Dict[str, int] = {}
        for node in self.nodes:
            node_type = node.get("method", "UNKNOWN")
            types[node_type] = types.get(node_type, 0) + 1
        return types

    def _get_node_color(
        self,
        content_type: str,
        score: float,
        pruned: bool,
        annotation: Mapping[str, Any] | None = None,
    ) -> str:
        if pruned:
            return "#cccccc"
        if annotation:
            return self.PRIORITY_COLORS.get(
                str(annotation.get("priority")), self.PRIORITY_COLORS["none"]
            )
        if content_type == "Text":
            return "#90EE90" if score > 0.5 else "#FFFFE0"
        if content_type == "Binary":
            return "#87CEEB" if score > 0.3 else "#DDA0DD"
        return "#F0F8FF"

    def _get_mermaid_brackets(
        self, content_type: str, score: float, pruned: bool
    ) -> tuple[str, str]:
        if pruned:
            return ('["', '"]')
        if content_type == "Text":
            return ('["', '"]') if score > 0.5 else ('(("', '"))')
        if content_type == "Binary":
            return ('["', '"]') if score > 0.3 else ('(("', '"))')
        return ('(("', '"))')

    @classmethod
    def _priority_for_score(cls, score: int) -> str:
        for threshold, label in cls.PRIORITY_CLASSES:
            if score >= threshold:
                return label
        return "none"

    @staticmethod
    def _safe_int(value: Any) -> int:
        try:
            return max(0, min(100, int(value or 0)))
        except (TypeError, ValueError):
            return 0

    @staticmethod
    def _safe_float(value: Any) -> float:
        try:
            return float(value or 0.0)
        except (TypeError, ValueError):
            return 0.0

    @staticmethod
    def _dot_id(value: Any) -> str:
        return f"node_{str(value).replace('-', '_')}"

    @staticmethod
    def _dot_escape(value: Any) -> str:
        return (
            str(value)
            .replace("\\", "\\\\")
            .replace('"', '\\"')
            .replace("\r", " ")
        )

    @staticmethod
    def _mermaid_id(value: Any) -> str:
        return f"node_{str(value).replace('-', '_')}"

    @staticmethod
    def _mermaid_text(value: Any) -> str:
        return (
            str(value or "")
            .replace("\r", " ")
            .replace("\n", " ")
            .replace("|", "/")
            .replace('"', "'")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .strip()
        )
