"""Correlation rules engine with starter detection rules.

Provides a library of behavioral detection rules that run against the analysis
graph and IOCs to flag suspicious patterns commonly seen in malware.
"""

from __future__ import annotations

from typing import Dict, Any, List, Callable, Sequence
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


class DetectionRule:
    """A single detection rule."""

    def __init__(
        self,
        rule_id: str,
        name: str,
        description: str,
        severity: str,
        detect_fn: Callable,
        attack_ids: Sequence[str] | None = None,
    ):
        self.rule_id = rule_id
        self.name = name
        self.description = description
        self.severity = severity  # low, medium, high, critical
        self.detect_fn = detect_fn
        # MITRE ATT&CK technique IDs this rule indicates. Static metadata:
        # consumed by the Threat Intelligence Engine as corroborating
        # detection evidence (see docs/THREAT_INTELLIGENCE.md).
        self.attack_ids = [str(t) for t in (attack_ids or [])]

    def evaluate(self, report: Dict[str, Any], iocs: Dict[str, Any]) -> bool:
        """Evaluate the rule against a report."""
        try:
            return self.detect_fn(report, iocs)
        except Exception as e:
            logger.error(f"Rule {self.rule_id} evaluation failed: {e}")
            return False


class CorrelationRulesEngine:
    """Correlation rules library with starter detection rules."""

    def __init__(self, rule_pack_paths: List[Path] | None = None):
        self.rules: List[DetectionRule] = []
        self.rule_packs: List[Dict[str, Any]] = []
        self._load_starter_rules()
        if rule_pack_paths:
            self.load_rule_packs(rule_pack_paths)

    def load_rule_packs(self, paths: List[Path]) -> None:
        """Load rule packs (JSON/YAML) and append their rules.

        Every rule definition is validated (see rule_packs.validate_rule_def);
        invalid rules and duplicate ids — within a pack, across packs, or
        colliding with a built-in rule — are skipped with a warning rather
        than loaded as silent no-ops. Per-pack loaded/skipped counts are
        recorded in ``self.rule_packs`` (and therefore in report meta).
        """
        from .rule_packs import (
            evaluate_pack_rule,
            load_rule_pack,
            validate_rule_def,
        )

        seen_ids = {rule.rule_id for rule in self.rules}

        for p in paths:
            try:
                info, rules = load_rule_pack(Path(p))
            except Exception as e:
                logger.warning("Failed to load rule pack %s: %s", p, e)
                continue

            pack_meta: Dict[str, Any] = {
                "name": info.name,
                "version": info.version,
                "schema_version": info.schema_version,
                "path": info.path,
                "rules_loaded": 0,
                "rules_skipped": 0,
            }
            self.rule_packs.append(pack_meta)

            for index, rule_def in enumerate(rules):
                problems = validate_rule_def(rule_def)
                rid = (
                    rule_def.get("id") if isinstance(rule_def, dict) else None
                )
                label = (
                    rid if isinstance(rid, str) and rid else f"rules[{index}]"
                )
                if problems:
                    pack_meta["rules_skipped"] += 1
                    logger.warning(
                        "Skipping invalid rule %s in pack %s: %s",
                        label,
                        info.name,
                        "; ".join(problems),
                    )
                    continue
                rid = str(rid)
                if rid in seen_ids:
                    pack_meta["rules_skipped"] += 1
                    logger.warning(
                        "Skipping rule %s in pack %s: duplicate of an "
                        "already-loaded rule id",
                        rid,
                        info.name,
                    )
                    continue
                seen_ids.add(rid)
                name = str(rule_def.get("name") or rid)
                desc = str(rule_def.get("description") or "")
                severity = str(rule_def.get("severity") or "low").lower()
                attack_ids = rule_def.get("attack_ids")
                if not isinstance(attack_ids, list):
                    attack_ids = []

                # Closure captures rule_def + pack info.
                def _fn(report, iocs, _rule_def=rule_def):
                    return evaluate_pack_rule(_rule_def, report, iocs)

                rule = DetectionRule(
                    rule_id=rid,
                    name=name,
                    description=desc,
                    severity=severity,
                    detect_fn=_fn,
                    attack_ids=[str(t) for t in attack_ids if t],
                )
                # Attach provenance for reporting.
                setattr(
                    rule,
                    "source",
                    {
                        "type": "pack",
                        "pack": info.name,
                        "pack_version": info.version,
                        "pack_path": info.path,
                    },
                )
                self.rules.append(rule)
                pack_meta["rules_loaded"] += 1

    def _load_starter_rules(self):
        """Load built-in starter detection rules."""

        # Rule 1: Deep Base64 nesting (common in obfuscated scripts)
        self.rules.append(
            DetectionRule(
                rule_id="TITAN-001",
                name="Deep Base64 Nesting",
                description="Multiple layers of Base64 encoding detected (3+ levels)",
                severity="medium",
                detect_fn=lambda report, iocs: self._detect_deep_base64(report),
                attack_ids=["T1027"],
            )
        )

        # Rule 2: Suspicious Office macro patterns
        self.rules.append(
            DetectionRule(
                rule_id="TITAN-002",
                name="Office Macro with Network IOCs",
                description="OLE file with embedded content and network indicators",
                severity="high",
                detect_fn=lambda report, iocs: self._detect_office_macro_network(
                    report, iocs
                ),
                attack_ids=["T1059.005", "T1204.002"],
            )
        )

        # Rule 3: Signed binary spawning script host (LOLBin pattern)
        self.rules.append(
            DetectionRule(
                rule_id="TITAN-003",
                name="LOLBin Script Execution Pattern",
                description="Content suggests legitimate binary executing scripts",
                severity="medium",
                detect_fn=lambda report, iocs: self._detect_lolbin_pattern(report),
                # Parent techniques: the rule fires on any LOLBin + abuse
                # context, so sub-technique attribution is left to the Threat
                # Intelligence Engine's per-binary LOLBin findings.
                attack_ids=["T1059", "T1218"],
            )
        )

        # Rule 4: High entropy data with low decoding success
        self.rules.append(
            DetectionRule(
                rule_id="TITAN-004",
                name="Encrypted or Packed Payload",
                description="High entropy data with minimal successful decoding",
                severity="low",
                detect_fn=lambda report, iocs: self._detect_encrypted_payload(report),
                attack_ids=["T1027"],
            )
        )

        # Rule 5: Multiple IOC types present
        self.rules.append(
            DetectionRule(
                rule_id="TITAN-005",
                name="Multi-Stage Infrastructure",
                description="Multiple IOC types suggest multi-stage attack infrastructure",
                severity="high",
                detect_fn=lambda report, iocs: self._detect_multistage_infra(
                    report, iocs
                ),
                attack_ids=["T1105"],
            )
        )

        # Rule 6: XOR encoding with network indicators
        self.rules.append(
            DetectionRule(
                rule_id="TITAN-006",
                name="XOR Obfuscation with C2",
                description="XOR-encoded content containing network IOCs",
                severity="high",
                detect_fn=lambda report, iocs: self._detect_xor_with_network(
                    report, iocs
                ),
                attack_ids=["T1027", "T1105"],
            )
        )

        # Rule 7: PDF with embedded executable content
        self.rules.append(
            DetectionRule(
                rule_id="TITAN-007",
                name="Malicious PDF",
                description="PDF containing PE or executable-like content",
                severity="critical",
                detect_fn=lambda report, iocs: self._detect_malicious_pdf(report),
                attack_ids=["T1204.002"],
            )
        )

        logger.info(f"Loaded {len(self.rules)} correlation rules")

    def _detect_deep_base64(self, report: Dict[str, Any]) -> bool:
        """Detect multiple layers of Base64 encoding.

        The engine collapses consecutive layers: a ``RecursiveBase64`` node
        peels several layers at once, so a 4-deep payload surfaces as just
        ``Base64`` -> ``RecursiveBase64`` (two nodes, depth 2) rather than four
        chained ``Base64`` nodes. Counting each ``RecursiveBase64`` node as the
        multiple layers it represents lets the rule catch that case while a
        single benign ``Base64`` node (layer score 1) stays below threshold.
        Tuned against tools/eval_detections.py: separates the deep-nesting
        sample from a plain single-layer base64 with no false positives.
        """
        nodes = report.get("nodes", [])
        max_depth = 0
        layer_score = 0

        for node in nodes:
            decoder = (node.get("decoder_used", "") or "").lower()
            if "recursivebase64" in decoder:
                layer_score += 2  # collapsed multi-layer peel
                max_depth = max(max_depth, node.get("depth", 0))
            elif "base64" in decoder:
                layer_score += 1
                max_depth = max(max_depth, node.get("depth", 0))

        return layer_score >= 3 or max_depth >= 4

    def _detect_office_macro_network(
        self, report: Dict[str, Any], iocs: Dict[str, Any]
    ) -> bool:
        """Detect Office documents with macros and network IOCs."""
        nodes = report.get("nodes", [])
        has_ole = any(
            "ole" in (
                (node.get("method", "") or "")
                + " "
                + ((node.get("decoder_used") or ""))
            ).lower()
            for node in nodes
        )
        has_network = bool(
            iocs.get("urls") or iocs.get("ipv4_public") or iocs.get("domains")
        )

        return has_ole and has_network

    # Living-off-the-land binaries commonly abused for execution.
    _LOLBINS = (
        "powershell",
        "cmd.exe",
        "wscript",
        "cscript",
        "mshta",
        "rundll32",
        "regsvr32",
    )

    # Strong abuse/execution-context indicators. A bare *mention* of a LOLBin
    # ("open PowerShell", "run cmd.exe") is common in benign documentation and
    # must NOT fire; the rule requires the LOLBin to co-occur with one of these
    # download-cradle / hidden-exec / script-COM tokens, which are rare in benign
    # prose. Kept as substrings so they match inside command lines regardless of
    # surrounding quoting.
    _LOLBIN_CONTEXT = (
        "-enc",
        "-encodedcommand",
        "-nop",
        "-noprofile",
        "-w hidden",
        "-windowstyle hidden",
        "-exec bypass",
        "executionpolicy bypass",
        "iex",
        "invoke-expression",
        "downloadstring",
        "downloadfile",
        "net.webclient",
        "/c ",
        "/k ",
        "scrobj.dll",
        "javascript:",
        "vbscript:",
        "/i:",
        "//nologo",
        ".sct",
    )

    def _detect_lolbin_pattern(self, report: Dict[str, Any]) -> bool:
        """Detect LOLBin *execution* patterns.

        Requires both a LOLBin name and a strong abuse-context token (encoded
        command, hidden window, download cradle, script-COM registration, …).
        This avoids the false positive where a benign document merely mentions
        "PowerShell" or "cmd.exe": the name alone is insufficient.
        """
        nodes = report.get("nodes", [])
        text = "\n".join(node.get("content_preview", "").lower() for node in nodes)

        if not any(lolbin in text for lolbin in self._LOLBINS):
            return False
        return any(ctx in text for ctx in self._LOLBIN_CONTEXT)

    def _detect_encrypted_payload(self, report: Dict[str, Any]) -> bool:
        """Detect high entropy payloads with minimal decoding."""
        nodes = report.get("nodes", [])

        if not nodes:
            return False

        root = nodes[0]
        root_entropy = root.get("entropy", 0)

        # High entropy at root with few successful decodes
        successful_decodes = sum(1 for n in nodes if n.get("decode_score", 0) > 0.5)

        return root_entropy > 7.5 and len(nodes) < 5 and successful_decodes <= 1

    def _detect_multistage_infra(
        self, report: Dict[str, Any], iocs: Dict[str, Any]
    ) -> bool:
        """Detect multi-stage attack infrastructure."""
        ioc_types = sum(
            [
                bool(iocs.get("urls")),
                bool(iocs.get("ipv4_public")),
                bool(iocs.get("domains")),
                bool(iocs.get("emails")),
            ]
        )

        return ioc_types >= 3

    def _detect_xor_with_network(
        self, report: Dict[str, Any], iocs: Dict[str, Any]
    ) -> bool:
        """Detect XOR encoding with network indicators."""
        nodes = report.get("nodes", [])
        has_xor = any(
            "xor" in (node.get("decoder_used") or "").lower() for node in nodes
        )
        has_network = bool(iocs.get("urls") or iocs.get("ipv4_public"))

        return has_xor and has_network

    def _detect_malicious_pdf(self, report: Dict[str, Any]) -> bool:
        """Detect PDFs with embedded executables."""
        nodes = report.get("nodes", [])
        has_pdf = any(
            "pdf" in (
                (node.get("method", "") or "")
                + " "
                + ((node.get("decoder_used") or ""))
            ).lower()
            for node in nodes
        )

        # Look for PE/ELF signatures in decoded content
        for node in nodes:
            preview = node.get("content_preview", "")
            if "MZ" in preview or "ELF" in preview:
                return has_pdf

        return False

    def evaluate_all(
        self, report: Dict[str, Any], iocs: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Evaluate all rules and return matches."""
        detections = []

        for rule in self.rules:
            if rule.evaluate(report, iocs):
                source = getattr(
                    rule,
                    "source",
                    {"type": "builtin", "pack": "titan_builtin"},
                )
                detections.append(
                    {
                        "rule_id": rule.rule_id,
                        "name": rule.name,
                        "description": rule.description,
                        "severity": rule.severity,
                        "attack_ids": list(rule.attack_ids),
                        "source": source,
                    }
                )
                logger.info(f"Detection: {rule.name} ({rule.rule_id})")

        return detections

    def add_custom_rule(self, rule: DetectionRule):
        """Add a custom detection rule."""
        self.rules.append(rule)
        logger.info(f"Added custom rule: {rule.name}")
