"""Deterministic analyst-oriented intelligence for Titan reports."""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Mapping, Sequence


class IntelligenceEngine:
    """Build an explainable intelligence summary from a Titan report."""

    CLASSIFICATIONS = (
        (81, "LIKELY_MALICIOUS"),
        (61, "HIGH_RISK_PAYLOAD"),
        (36, "SUSPICIOUS_OBJECT"),
        (16, "LOW_RISK_ARTIFACT"),
        (0, "CLEAN"),
    )

    EXECUTION_PATTERNS = (
        re.compile(r"\bpowershell(?:\.exe)?\b", re.IGNORECASE),
        re.compile(r"\bcmd(?:\.exe)?\s+/[ck]\b", re.IGNORECASE),
        re.compile(r"\b(?:wscript|cscript)(?:\.exe)?\b", re.IGNORECASE),
        re.compile(r"\b(?:mshta|rundll32|regsvr32)(?:\.exe)?\b", re.IGNORECASE),
        re.compile(r"\b(?:javascript|vbscript):", re.IGNORECASE),
        re.compile(r"\b(?:curl|wget)\s+https?://", re.IGNORECASE),
        re.compile(r"\b(?:iex|invoke-expression)\b", re.IGNORECASE),
        re.compile(r"\bdownloadstring\b", re.IGNORECASE),
    )

    EXECUTABLE_SIGNATURES = (
        ("PE executable", "MZ"),
        ("ELF executable", "\x7fELF"),
        ("PDF document", "%PDF"),
        ("ZIP archive", "PK\x03\x04"),
    )

    def analyze(
        self,
        report: Mapping[str, Any],
        iocs: Mapping[str, Sequence[Any]] | None = None,
        detections: Sequence[Mapping[str, Any]] | None = None,
        risk: Mapping[str, Any] | None = None,
    ) -> Dict[str, Any]:
        nodes = list(report.get("nodes") or [])
        iocs = iocs or report.get("iocs") or {}
        detections = list(
            detections if detections is not None else report.get("detections") or []
        )
        risk = risk or report.get("risk_assessment") or {}

        signals: List[Dict[str, Any]] = []
        score = 0

        def add_signal(code: str, points: int, summary: str, evidence: Any = None) -> None:
            nonlocal score
            score += points
            signal: Dict[str, Any] = {
                "code": code,
                "points": points,
                "summary": summary,
            }
            if evidence not in (None, [], {}, ""):
                signal["evidence"] = evidence
            signals.append(signal)

        if detections:
            severity_points = {"critical": 35, "high": 30, "medium": 20, "low": 8}
            severities = [
                str(item.get("severity", "low")).lower() for item in detections
            ]
            strongest = max(
                severities,
                key=lambda value: severity_points.get(value, 5),
                default="low",
            )
            add_signal(
                "detection_rules",
                severity_points.get(strongest, 5),
                f"{len(detections)} detection rule(s) triggered; strongest severity is {strongest}",
                [item.get("name") or item.get("id") for item in detections[:5]],
            )

        urls = self._count(iocs, "urls")
        public_ips = self._count(iocs, "ipv4_public")
        domains = self._count(iocs, "domains")
        if urls:
            add_signal("network_urls", min(18, 10 + urls * 2), f"{urls} URL indicator(s) discovered")
        if public_ips:
            add_signal(
                "network_public_ips",
                min(16, 7 + public_ips * 2),
                f"{public_ips} public IP indicator(s) discovered",
            )
        if domains:
            add_signal(
                "network_domains",
                min(10, 3 + domains),
                f"{domains} domain indicator(s) discovered",
            )

        max_depth = max((self._safe_int(node.get("depth")) for node in nodes), default=0)
        if max_depth >= 4:
            add_signal(
                "deep_obfuscation",
                min(16, 8 + (max_depth - 4) * 2),
                f"Deep decoding chain reached depth {max_depth}",
            )

        high_entropy_nodes = [
            node for node in nodes if self._safe_float(node.get("entropy")) >= 7.5
        ]
        if high_entropy_nodes:
            add_signal(
                "high_entropy",
                10,
                "High-entropy content may be packed, compressed, or encrypted",
                [node.get("id") for node in high_entropy_nodes[:5]],
            )

        execution_nodes = []
        executable_nodes = []
        for node in nodes:
            preview = str(node.get("content_preview") or node.get("preview") or "")
            if preview and any(pattern.search(preview) for pattern in self.EXECUTION_PATTERNS):
                execution_nodes.append(node.get("id"))

            for label, signature in self.EXECUTABLE_SIGNATURES:
                if preview.startswith(signature):
                    executable_nodes.append({"node_id": node.get("id"), "type": label})
                    break

        if execution_nodes:
            add_signal(
                "execution_context",
                16,
                "Command or script execution context was found",
                execution_nodes[:5],
            )

        if executable_nodes:
            add_signal(
                "embedded_structure",
                10,
                "Executable or structured file content was revealed",
                executable_nodes[:5],
            )

        risk_level = str(risk.get("risk_level") or "").upper()
        risk_score = self._safe_int(risk.get("risk_score"))
        if risk_level in {"HIGH", "CRITICAL"}:
            add_signal(
                "risk_alignment",
                12 if risk_level == "HIGH" else 15,
                f"Existing risk engine classified the analysis as {risk_level}",
                risk_score,
            )
        elif risk_level == "MEDIUM":
            add_signal(
                "risk_alignment",
                5,
                "Existing risk engine classified the analysis as MEDIUM",
                risk_score,
            )

        score = max(0, min(score, 100))
        return {
            "version": "1.0",
            "intelligence_score": score,
            "classification": self.classify(score),
            "confidence": round(score / 100.0, 2),
            "signals": signals,
            "top_artifacts": self.rank_nodes(nodes, limit=5),
            "recommendation": self.recommendation(score),
        }

    def rank_nodes(
        self,
        nodes: Iterable[Mapping[str, Any]],
        limit: int = 5,
    ) -> List[Dict[str, Any]]:
        ranked: List[Dict[str, Any]] = []
        for node in nodes:
            points = 0
            reasons: List[str] = []
            entropy = self._safe_float(node.get("entropy"))
            depth = self._safe_int(node.get("depth"))
            decode_score = self._safe_float(node.get("decode_score"))
            preview = str(node.get("content_preview") or node.get("preview") or "")

            if entropy >= 7.5:
                points += 20
                reasons.append("high entropy")
            if depth >= 4:
                points += min(20, depth * 3)
                reasons.append(f"deep decode depth {depth}")
            if decode_score >= 0.7:
                points += 15
                reasons.append("high-confidence transformation")
            if any(pattern.search(preview) for pattern in self.EXECUTION_PATTERNS):
                points += 30
                reasons.append("execution context")
            if "http://" in preview.lower() or "https://" in preview.lower():
                points += 15
                reasons.append("network indicator")
            if any(preview.startswith(signature) for _, signature in self.EXECUTABLE_SIGNATURES):
                points += 20
                reasons.append("structured file signature")

            if points:
                ranked.append(
                    {
                        "node_id": node.get("id"),
                        "artifact_name": node.get("artifact_name"),
                        "method": node.get("method"),
                        "score": min(points, 100),
                        "reasons": reasons,
                    }
                )

        ranked.sort(
            key=lambda item: (
                -self._safe_int(item.get("score")),
                self._safe_int(item.get("node_id")),
            )
        )
        return ranked[: max(0, limit)]

    @classmethod
    def classify(cls, score: int) -> str:
        for threshold, label in cls.CLASSIFICATIONS:
            if score >= threshold:
                return label
        return "CLEAN"

    @staticmethod
    def recommendation(score: int) -> str:
        if score >= 81:
            return "Immediate analyst review and containment triage"
        if score >= 61:
            return "High-priority manual review"
        if score >= 36:
            return "Review the highest-ranked decoded artifacts"
        if score >= 16:
            return "Low-priority inspection; correlate with case context"
        return "No additional action indicated by the intelligence layer"

    @staticmethod
    def _count(mapping: Mapping[str, Sequence[Any]], key: str) -> int:
        value = mapping.get(key) or []
        try:
            return len(value)
        except TypeError:
            return 0

    @staticmethod
    def _safe_int(value: Any) -> int:
        try:
            return int(value or 0)
        except (TypeError, ValueError):
            return 0

    @staticmethod
    def _safe_float(value: Any) -> float:
        try:
            return float(value or 0.0)
        except (TypeError, ValueError):
            return 0.0
