"""Correlation rules engine with starter detection rules.

Provides a library of behavioral detection rules that run against the analysis
graph and IOCs to flag suspicious patterns commonly seen in malware.
"""

from __future__ import annotations

from typing import Dict, Any, List, Callable, Sequence
import logging
from pathlib import Path
import re

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
                rid = rule_def.get("id") if isinstance(rule_def, dict) else None
                label = rid if isinstance(rid, str) and rid else f"rules[{index}]"
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
                description="OLE macro content with network indicators",
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

        # Rule 4: High-entropy executable/packer context with low decode success.
        # Generic ciphertext and incompressible user data remain entropy signals
        # in risk scoring but are not, by themselves, detections.
        self.rules.append(
            DetectionRule(
                rule_id="TITAN-004",
                name="Opaque Executable Payload",
                description=(
                    "High-entropy executable or packer content with minimal "
                    "successful decoding"
                ),
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
                description=(
                    "Multiple IOC types with C2, beacon, or exfiltration context"
                ),
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

        # Rule 8: payload hidden in image/media data.  This indicates a
        # concealment technique, not by itself a malicious verdict; recovered
        # content is separately scanned by all normal Titan controls.
        self.rules.append(
            DetectionRule(
                rule_id="TITAN-008",
                name="Hidden Media Payload",
                description=(
                    "A payload was recovered from image/media trailing data, "
                    "metadata, or least-significant bits"
                ),
                severity="medium",
                detect_fn=lambda report, iocs: self._detect_hidden_media_payload(
                    report
                ),
                attack_ids=["T1027.003"],
            )
        )

        logger.info(f"Loaded {len(self.rules)} correlation rules")

    @staticmethod
    def _node_id(node: Dict[str, Any]) -> Any:
        """Return either supported report-schema node identifier."""
        if node.get("id") is not None:
            return node.get("id")
        return node.get("node_id")

    @classmethod
    def _descendant_nodes(
        cls, nodes: List[Dict[str, Any]], root: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Return *root* and nodes descended from it.

        Correlation rules must not combine evidence from sibling decode branches.
        Reports always carry ``id``/``parent``; the one-node fallback preserves
        safe behavior for small hand-built reports that omit graph identifiers.
        """
        root_id = cls._node_id(root)
        if root_id is None:
            return [root]

        children: Dict[Any, List[Dict[str, Any]]] = {}
        for node in nodes:
            parent = node.get("parent") if "parent" in node else node.get("parent_id")
            if parent is not None:
                children.setdefault(parent, []).append(node)

        selected: List[Dict[str, Any]] = []
        queue = [root]
        visited: set[tuple[str, Any]] = set()
        while queue:
            node = queue.pop()
            node_id = cls._node_id(node)
            visit_key = (
                ("node", node_id) if node_id is not None else ("object", id(node))
            )
            if visit_key in visited:
                continue
            visited.add(visit_key)
            selected.append(node)
            if node_id is not None:
                queue.extend(children.get(node_id, ()))
        return selected

    @staticmethod
    def _content_text(nodes: Sequence[Dict[str, Any]]) -> str:
        return "\n".join(str(node.get("content_preview") or "") for node in nodes)

    @staticmethod
    def _ioc_markers(iocs: Dict[str, Any], *keys: str) -> List[str]:
        markers: List[str] = []
        for key in keys:
            values = iocs.get(key) or []
            if isinstance(values, str):
                values = [values]
            markers.extend(str(value).lower() for value in values if value)
        return markers

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

        def weight(node: Dict[str, Any]) -> int:
            decoder = str(node.get("decoder_used") or "").lower()
            if "recursivebase64" in decoder:
                return 2  # collapsed multi-layer peel
            if "base64" in decoder:
                return 1
            return 0

        # A legacy hand-built report may omit graph ids. Only treat it as one
        # path when every node has a unique depth; otherwise branch correlation
        # is unknowable and the safe result is no match.
        if nodes and not any(self._node_id(node) is not None for node in nodes):
            depths = [node.get("depth") for node in nodes]
            if None in depths or len(set(depths)) != len(depths):
                return False
            return sum(weight(node) for node in nodes) >= 3

        # Propagate the Base64 layer score down each lineage independently.
        # Three unrelated single-layer Base64 branches must not add up to a
        # deep-nesting detection.
        scores: Dict[Any, int] = {}
        for node in sorted(nodes, key=lambda item: int(item.get("depth") or 0)):
            node_id = self._node_id(node)
            if node_id is None:
                continue
            parent = node.get("parent") if "parent" in node else node.get("parent_id")
            scores[node_id] = scores.get(parent, 0) + weight(node)
            if scores[node_id] >= 3:
                return True
        return False

    def _detect_office_macro_network(
        self, report: Dict[str, Any], iocs: Dict[str, Any]
    ) -> bool:
        """Detect Office documents with macros and network IOCs."""
        nodes = report.get("nodes", [])
        network_markers = self._ioc_markers(iocs, "urls", "ipv4_public", "domains")
        if not network_markers:
            return False

        macro_markers = (
            "macros/vba/",
            "attribute vb_name",
            "_vba_project",
            "vba project",
        )
        for node in nodes:
            operation = (
                str(node.get("method") or "")
                + " "
                + str(node.get("decoder_used") or "")
            ).lower()
            if "ole" not in operation:
                continue
            text = self._content_text(self._descendant_nodes(nodes, node)).lower()
            has_macro = any(marker in text for marker in macro_markers)
            has_network = any(marker in text for marker in network_markers)
            if has_macro and has_network:
                return True
        return False

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
    # prose. Regex token boundaries prevent benign options such as ``-Encoding``
    # from being mistaken for the encoded-command abbreviation ``-enc``.
    _LOLBIN_CONTEXT = tuple(
        re.compile(pattern, re.IGNORECASE)
        for pattern in (
            r"(?<![\w-])-(?:enc|encodedcommand)(?=$|[\s:=])",
            r"(?<![\w-])-(?:w|windowstyle)\s+hidden\b",
            r"(?<![\w-])-(?:exec|executionpolicy)\s+bypass\b",
            r"(?<![\w-])iex(?=$|[\s;(])",
            r"\binvoke-expression\b",
            r"\bdownload(?:string|file)\b",
            r"\bnet\.webclient\b",
            r"\bscrobj\.dll\b",
            r"\b(?:java|vb)script:",
            r"(?<!\w)/i:(?:https?://|\S*\.sct\b)",
            r"\.sct\b",
        )
    )

    def _detect_lolbin_pattern(self, report: Dict[str, Any]) -> bool:
        """Detect LOLBin *execution* patterns.

        Requires both a LOLBin name and a strong abuse-context token (encoded
        command, hidden window, download cradle, script-COM registration, …).
        This avoids the false positive where a benign document merely mentions
        "PowerShell" or "cmd.exe": the name alone is insufficient.
        """
        for node in report.get("nodes", []):
            text = str(node.get("content_preview") or "").lower()
            if not any(lolbin in text for lolbin in self._LOLBINS):
                continue
            if any(pattern.search(text) for pattern in self._LOLBIN_CONTEXT):
                return True
        return False

    def _detect_encrypted_payload(self, report: Dict[str, Any]) -> bool:
        """Detect opaque executable/packer content with minimal decoding.

        Entropy alone cannot distinguish packed malware from encrypted backups,
        compressed user data, or cryptographic material. Requiring executable
        magic or a packer marker keeps the rule actionable while the separate
        entropy risk signal still records generic high-entropy inputs.
        """
        nodes = report.get("nodes", [])

        if not nodes:
            return False

        root = nodes[0]
        root_entropy = root.get("entropy", 0)
        root_preview = str(root.get("content_preview") or "")
        has_executable_magic = root_preview.startswith(("MZ", "\x7fELF", "ELF"))
        has_packer_marker = any(
            "upx" in str(node.get("content_preview") or "").lower() for node in nodes
        )

        # High entropy at root with few successful decodes and concrete binary
        # context. A raw random/ciphertext blob intentionally stays below this
        # detection boundary.
        successful_decodes = sum(1 for n in nodes if n.get("decode_score", 0) > 0.5)

        return (
            root_entropy > 7.5
            and len(nodes) < 5
            and successful_decodes <= 1
            and (has_executable_magic or has_packer_marker)
        )

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

        if ioc_types < 3:
            return False

        # Common documentation and inventory records legitimately contain a
        # URL, host/IP, and support email. Require high-signal staging context
        # before promoting that IOC diversity to a behavioral detection.
        text = self._content_text(report.get("nodes", []))
        return bool(
            re.search(
                r"\b(?:c2|command[- ]and[- ]control|beacon(?:ing)?|"
                r"exfil(?:trate|tration|trated|trating)?)\b",
                text,
                re.IGNORECASE,
            )
        )

    def _detect_xor_with_network(
        self, report: Dict[str, Any], iocs: Dict[str, Any]
    ) -> bool:
        """Detect XOR encoding with network indicators."""
        nodes = report.get("nodes", [])
        network_markers = self._ioc_markers(iocs, "urls", "ipv4_public")
        if not network_markers:
            return False
        for node in nodes:
            if "xor" not in str(node.get("decoder_used") or "").lower():
                continue
            text = self._content_text(self._descendant_nodes(nodes, node)).lower()
            if any(marker in text for marker in network_markers):
                return True
        return False

    def _detect_malicious_pdf(self, report: Dict[str, Any]) -> bool:
        """Detect PDFs with embedded executables."""
        nodes = report.get("nodes", [])
        for node in nodes:
            operation = (
                str(node.get("method") or "")
                + " "
                + str(node.get("decoder_used") or "")
            ).lower()
            if "pdf" not in operation:
                continue
            for descendant in self._descendant_nodes(nodes, node):
                preview = str(descendant.get("content_preview") or "")
                # Require binary magic at the start of content or an extracted
                # stream line. Plain prose that merely discusses "MZ" or "ELF"
                # is not embedded executable evidence.
                if re.search(
                    r"(?:\A|[\r\n])(?:MZ(?=[\x00-\x1f\x7f-\xff])|\x7fELF)",
                    preview,
                ):
                    return True
        return False

    def _detect_hidden_media_payload(self, report: Dict[str, Any]) -> bool:
        """Detect successful output from the bounded media analyzer."""
        for node in report.get("nodes", []):
            method = str(node.get("method") or "").lower()
            decoder = str(node.get("decoder_used") or "").lower()
            artifact = str(node.get("artifact_name") or "").lower()
            if "steganography" in method or "steganography" in decoder:
                return True
            if artifact.startswith("steg_"):
                return True
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
