"""Risk scoring engine for heuristic threat assessment.

Computes an overall risk score for analysis runs based on detection rules,
IOC counts, entropy, obfuscation depth, and other heuristics.
"""

from __future__ import annotations

from typing import Dict, Any, List
import logging

logger = logging.getLogger(__name__)


class RiskScoringEngine:
    """Compute risk scores for analyses.

    Weight validation
    -----------------
    These 0--100 weights are measured against the synthetic labeled corpus in
    ``tools/corpus_samples.py`` via ``tools/eval_detections.py`` (results
    committed in ``docs/detection_metrics.json`` and summarized in
    ``docs/DETECTION_QUALITY.md``). As of the last run over the expanded corpus
    (14 malicious / 12 benign, two positives per rule plus adversarial benign
    near-misses): every built-in rule (TITAN-001..007) scores precision 1.000 /
    recall 1.000, and the overall risk score cleanly separates the classes —
    benign samples score at most 7 while every malicious sample scores at least
    15 (no overlap). ``tests/test_detection_eval.py`` asserts this separation so
    a weight or rule change that regresses it fails CI. Re-run the harness and
    refresh the metrics file when tuning these constants.

    A per-severity floor (``SEVERITY_FLOOR``) additionally guarantees a fired
    rule never reads below its own severity, so a genuine detection is not
    under-prioritized as LOW.
    """

    # Scoring weights (see "Weight validation" above).
    WEIGHT_DETECTION_CRITICAL = 40
    WEIGHT_DETECTION_HIGH = 25
    WEIGHT_DETECTION_MEDIUM = 15
    WEIGHT_DETECTION_LOW = 5

    # Per-severity risk-level floor: a fired detection rule must never let the
    # overall assessment read *below* the rule's own severity. Without this, a
    # single medium-severity correlation rule contributes only
    # WEIGHT_DETECTION_MEDIUM (15) — under the MEDIUM threshold (25) — so a fired
    # "LOLBin Script Execution" or "Deep Base64 Nesting" rule read LOW, which is
    # counterintuitive for an analyst triaging the result. These values are the
    # minimum normalized score each severity guarantees and are aligned with the
    # risk-level thresholds below (MEDIUM=25, HIGH=50, CRITICAL=75). The additive
    # weights can still push *higher*; the floor only prevents reading lower.
    # Benign inputs fire no rules (measured precision 1.000 on the corpus), so
    # this only ever lifts true detections and cannot worsen class separation.
    SEVERITY_FLOOR = {"low": 0, "medium": 25, "high": 50, "critical": 75}
    WEIGHT_IOC_PUBLIC_IP = 3
    WEIGHT_IOC_URL = 4
    WEIGHT_IOC_DOMAIN = 3
    WEIGHT_IOC_EMAIL = 2
    WEIGHT_OBFUSCATION_DEPTH = 2  # per level
    WEIGHT_HIGH_ENTROPY = 10
    WEIGHT_YARA_MATCH = 20

    def __init__(self):
        pass

    def compute_risk_score(
        self,
        report: Dict[str, Any],
        iocs: Dict[str, Any],
        detections: List[Dict[str, Any]],
        enrichment: Dict[str, Any] = None,
        yara_matches: List[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Compute comprehensive risk score."""

        score = 0
        breakdown = {}
        reasons = []

        # Detection rules
        detection_score = 0
        detection_floor = 0
        floor_severity = None
        for det in detections:
            severity = det.get("severity", "low")
            floor = self.SEVERITY_FLOOR.get(severity, 0)
            if floor > detection_floor:
                detection_floor = floor
                floor_severity = severity
            if severity == "critical":
                detection_score += self.WEIGHT_DETECTION_CRITICAL
                reasons.append(f"Critical: {det['name']}")
            elif severity == "high":
                detection_score += self.WEIGHT_DETECTION_HIGH
                reasons.append(f"High: {det['name']}")
            elif severity == "medium":
                detection_score += self.WEIGHT_DETECTION_MEDIUM
            elif severity == "low":
                detection_score += self.WEIGHT_DETECTION_LOW

        breakdown["detections"] = detection_score
        score += detection_score

        # IOC scoring
        ioc_score = 0
        public_ips = len(iocs.get("ipv4_public", []))
        urls = len(iocs.get("urls", []))
        domains = len(iocs.get("domains", []))
        emails = len(iocs.get("emails", []))

        ioc_score += min(public_ips * self.WEIGHT_IOC_PUBLIC_IP, 30)
        ioc_score += min(urls * self.WEIGHT_IOC_URL, 40)
        ioc_score += min(domains * self.WEIGHT_IOC_DOMAIN, 30)
        ioc_score += min(emails * self.WEIGHT_IOC_EMAIL, 10)

        if public_ips > 0:
            reasons.append(f"{public_ips} public IP(s)")
        if urls > 0:
            reasons.append(f"{urls} URL(s)")
        if domains > 3:
            reasons.append(f"{domains} domains")

        breakdown["iocs"] = ioc_score
        score += ioc_score

        # Obfuscation depth
        nodes = report.get("nodes", [])
        max_depth = max((n.get("depth", 0) for n in nodes), default=0)
        depth_score = min(max_depth * self.WEIGHT_OBFUSCATION_DEPTH, 20)

        if max_depth >= 4:
            reasons.append(f"Deep obfuscation ({max_depth} levels)")

        breakdown["obfuscation"] = depth_score
        score += depth_score

        # High entropy (encrypted/packed)
        entropy_score = 0
        for node in nodes[:3]:  # Check first 3 nodes
            if node.get("entropy", 0) > 7.5:
                entropy_score += self.WEIGHT_HIGH_ENTROPY
                reasons.append("High entropy payload detected")
                break

        breakdown["entropy"] = entropy_score
        score += entropy_score

        # YARA matches
        yara_score = 0
        if yara_matches:
            yara_score = min(len(yara_matches) * self.WEIGHT_YARA_MATCH, 60)
            for match in yara_matches[:3]:
                reasons.append(f"YARA: {match['rule']}")

        breakdown["yara"] = yara_score
        score += yara_score

        # Enrichment-based scoring (malicious IPs from threat intel)
        enrichment_score = 0
        if enrichment:
            # Future: Check for known malicious IPs/domains from enrichment
            pass

        breakdown["enrichment"] = enrichment_score
        score += enrichment_score

        # Apply the per-severity floor: a fired rule must not read below its own
        # severity (see SEVERITY_FLOOR). Applied after summing, so additive
        # signal still pushes higher, but the score can never fall under the
        # strongest fired rule's floor. ``raw_score`` keeps the pure additive
        # value for transparency.
        if detection_floor > score:
            reasons.insert(
                0, f"Risk floored to {floor_severity} by fired detection rule"
            )
        breakdown["detection_floor"] = detection_floor

        # Normalize to 0-100
        normalized_score = min(max(score, detection_floor), 100)

        # Risk level
        if normalized_score >= 75:
            risk_level = "CRITICAL"
        elif normalized_score >= 50:
            risk_level = "HIGH"
        elif normalized_score >= 25:
            risk_level = "MEDIUM"
        elif normalized_score > 0:
            risk_level = "LOW"
        else:
            risk_level = "CLEAN"

        return {
            "risk_score": normalized_score,
            "risk_level": risk_level,
            "breakdown": breakdown,
            "top_reasons": reasons[:5],  # Top 5 reasons
            "raw_score": score,
        }

    def get_top_risky_nodes(
        self, report: Dict[str, Any], limit: int = 5
    ) -> List[Dict[str, Any]]:
        """Identify top risky nodes in the analysis tree."""
        nodes = report.get("nodes", [])

        # Score each node
        scored_nodes = []
        for node in nodes:
            node_score = 0

            # High entropy
            if node.get("entropy", 0) > 7.0:
                node_score += 20

            # Successful decode with high score
            if node.get("decode_score", 0) > 0.7:
                node_score += 15

            # Contains executable signatures
            preview = node.get("content_preview", "")
            if "MZ" in preview or "ELF" in preview:
                node_score += 30

            # Deep in tree (more obfuscation layers)
            node_score += node.get("depth", 0) * 5

            scored_nodes.append(
                {
                    "node_id": node.get("id"),
                    "risk_score": node_score,
                    "method": node.get("method"),
                    "decoder": node.get("decoder_used"),
                    "depth": node.get("depth"),
                    "sha256": node.get("sha256"),
                }
            )

        # Sort by score and return top N
        scored_nodes.sort(key=lambda x: x["risk_score"], reverse=True)
        return scored_nodes[:limit]
