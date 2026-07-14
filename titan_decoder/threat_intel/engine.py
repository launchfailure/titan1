"""Threat Intelligence Engine v1."""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any, Dict, Iterable, List, Mapping, Sequence

from .catalog import load_attack_catalog
from .lolbins import identify_lolbins
from .malware import identify_malware_tags
from .models import AttackTechniqueFinding, ThreatAssessment


class ThreatIntelligenceEngine:
    """Map Titan evidence to deterministic ATT&CK, LOLBin, and malware tags."""

    VERSION = "1.0"

    BEHAVIOR_RULES = (
        # Requires a retrieval verb; a bare URL is not evidence of tool
        # transfer (URL-only indicators stay in the IOC summary).
        ("T1105", re.compile(r"(?i)\b(?:downloadstring|downloadfile|invoke-webrequest|curl|wget|urlretrieve|start-bitstransfer)\b"), "network-transfer"),
        ("T1027", re.compile(r"(?i)(?:\bfrombase64string\b|-enc(?:odedcommand)?\b|\b(?:base64|xor|gzip|deflate)\b)"), "obfuscation"),
        ("T1140", re.compile(r"(?i)\b(?:frombase64string|convert\.frombase64|certutil\s+-decode|decompress|inflate)\b"), "decode"),
        ("T1053.005", re.compile(r"(?i)\bschtasks(?:\.exe)?\b.*\/(?:create|run)\b"), "scheduled-task"),
        ("T1547.001", re.compile(r"(?i)\breg(?:\.exe)?\s+add\b.*\\(?:run|runonce)\b"), "run-key"),
        ("T1003", re.compile(r"(?i)\b(?:mimikatz|sekurlsa|lsass|ntds\.dit|sam\s+hive)\b"), "credential-access"),
        ("T1082", re.compile(r"(?i)\b(?:systeminfo|hostname|wmic\s+os)\b"), "system-discovery"),
        ("T1083", re.compile(r"(?i)\b(?:dir\s+\/s|Get-ChildItem|findstr)\b"), "file-discovery"),
        ("T1562.001", re.compile(r"(?i)\b(?:set-mppreference|disableantispyware|stop-service\s+windefend|sc\s+stop)\b"), "impair-defenses"),
        ("T1490", re.compile(r"(?i)\b(?:vssadmin\s+delete\s+shadows|wbadmin\s+delete\s+catalog|wmic\s+shadowcopy\s+delete|bcdedit\b.{0,40}recoveryenabled\s+no)\b"), "inhibit-recovery"),
        ("T1016", re.compile(r"(?i)\b(?:ipconfig|ifconfig|route\s+print|nltest\s+/domain)"), "network-config-discovery"),
        ("T1033", re.compile(r"(?i)\bwhoami\b"), "user-discovery"),
        ("T1036", re.compile(r"(?i)\.(?:pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt)\.(?:exe|scr|com|pif|bat|cmd|js|vbs|hta)\b"), "double-extension"),
        ("T1053.003", re.compile(r"(?i)(?:\bcrontab\b|/etc/cron)"), "cron-schedule"),
        ("T1057", re.compile(r"(?i)(?:\btasklist\b|\bget-process\b|\bps\s+aux\b)"), "process-discovery"),
        ("T1059.004", re.compile(r"(?i)(?:/bin/(?:ba)?sh\b|\b(?:ba)?sh\s+-c\s)"), "unix-shell"),
        ("T1059.006", re.compile(r"(?i)\bpython(?:3(?:\.\d+)?)?(?:\.exe)?\s+-c\s"), "python-inline-exec"),
        ("T1070.004", re.compile(r"(?i)(?:\bdel\s+/[fqs]\b|\brm\s+-(?:rf|fr)\b|\bsdelete\b|\bremove-item\b.{0,60}-recurse|\bcipher\s+/w:)"), "file-deletion"),
        ("T1087", re.compile(r"(?i)(?:\bnet\s+(?:user|localgroup)\b|\bget-localuser\b)"), "account-discovery"),
        ("T1112", re.compile(r"(?i)\breg(?:\.exe)?\s+(?:add|delete)\b"), "registry-modification"),
        ("T1489", re.compile(r"(?i)(?:\bnet\s+stop\b|\btaskkill\s+/f\b|\bstop-service\b)"), "service-stop"),
        ("T1543.003", re.compile(r"(?i)(?:\bsc(?:\.exe)?\s+create\b|\bnew-service\b)"), "service-install"),
        ("T1552.001", re.compile(r"(?i)(?:\bfindstr\s+/si\s+password\b|\bgrep\s+-ri?\s+password\b)"), "credentials-in-files"),
    )

    def analyze(
        self,
        report: Mapping[str, Any],
        iocs: Mapping[str, Sequence[Any]] | None = None,
        detections: Sequence[Mapping[str, Any]] | None = None,
    ) -> Dict[str, Any]:
        nodes = [
            item
            for item in (report.get("nodes") or [])
            if isinstance(item, Mapping)
        ]
        iocs = iocs or report.get("iocs") or {}
        detections = list(
            detections
            if detections is not None
            else report.get("detections") or []
        )

        catalog = load_attack_catalog()
        by_id = catalog["by_id"]
        lolbins = identify_lolbins(nodes)
        malware_tags = identify_malware_tags(nodes, lolbins, iocs)

        evidence_by_technique: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        rules_by_technique: Dict[str, List[str]] = defaultdict(list)

        for finding in lolbins:
            for technique_id in finding.technique_ids:
                evidence_by_technique[technique_id].append(
                    {
                        "kind": "lolbin",
                        "value": finding.executable,
                        "node_ids": list(finding.node_ids),
                    }
                )
                rules_by_technique[technique_id].append(
                    f"lolbin:{finding.executable}"
                )

        for node in nodes:
            text = self._node_text(node)
            for technique_id, pattern, rule_name in self.BEHAVIOR_RULES:
                if pattern.search(text):
                    evidence_by_technique[technique_id].append(
                        {
                            "kind": "node",
                            "node_id": node.get("id"),
                            "preview": text[:160],
                        }
                    )
                    rules_by_technique[technique_id].append(rule_name)

        for detection in detections:
            attack_ids = (
                detection.get("attack_ids")
                or detection.get("mitre_attack")
                or []
            )
            if isinstance(attack_ids, str):
                attack_ids = [attack_ids]
            for technique_id in attack_ids:
                if technique_id in by_id:
                    evidence_by_technique[technique_id].append(
                        {
                            "kind": "detection",
                            "detection_id": detection.get("id"),
                            "name": detection.get("name"),
                        }
                    )
                    rules_by_technique[technique_id].append(
                        "detection-metadata"
                    )

        techniques: List[AttackTechniqueFinding] = []
        for technique_id in sorted(evidence_by_technique):
            catalog_item = by_id.get(technique_id)
            if not catalog_item:
                continue
            evidence = self._deduplicate_evidence(
                evidence_by_technique[technique_id]
            )
            source_rules = sorted(
                set(rules_by_technique[technique_id])
            )
            techniques.append(
                AttackTechniqueFinding(
                    technique_id=technique_id,
                    name=str(catalog_item["name"]),
                    tactics=list(catalog_item.get("tactics") or []),
                    confidence=self._finding_confidence(
                        evidence, source_rules
                    ),
                    evidence=evidence,
                    source_rules=source_rules,
                )
            )

        techniques.sort(
            key=lambda item: (-item.confidence, item.technique_id)
        )
        tactics = sorted(
            {tactic for item in techniques for tactic in item.tactics}
        )
        relationships = self._relationships(
            techniques, lolbins, malware_tags
        )
        confidence = self._assessment_confidence(
            techniques, lolbins, malware_tags
        )

        assessment = ThreatAssessment(
            version=self.VERSION,
            catalog_version=str(
                catalog.get("catalog_version") or "unknown"
            ),
            techniques=techniques,
            tactics=tactics,
            lolbins=lolbins,
            malware_tags=malware_tags,
            relationships=relationships,
            confidence=confidence,
            summary=self._summary(
                techniques, lolbins, malware_tags
            ),
        )
        return assessment.to_dict()

    @staticmethod
    def _node_text(node: Mapping[str, Any]) -> str:
        return " ".join(
            str(node.get(key) or "")
            for key in (
                "content_preview",
                "preview",
                "artifact_name",
                "method",
                "decoder_used",
            )
        )

    @staticmethod
    def _deduplicate_evidence(
        items: Iterable[Mapping[str, Any]],
    ) -> List[Dict[str, Any]]:
        unique: Dict[str, Dict[str, Any]] = {}
        for item in items:
            normalized = dict(item)
            key = repr(
                sorted(
                    (str(k), repr(v))
                    for k, v in normalized.items()
                )
            )
            unique[key] = normalized
        return [unique[key] for key in sorted(unique)]

    @staticmethod
    def _finding_confidence(
        evidence: Sequence[Mapping[str, Any]],
        source_rules: Sequence[str],
    ) -> float:
        source_kinds = {
            str(item.get("kind"))
            for item in evidence
        }
        value = 0.45 + min(0.25, len(evidence) * 0.07)
        value += min(0.15, len(source_kinds) * 0.05)
        value += min(0.10, len(source_rules) * 0.03)
        return round(min(0.98, value), 2)

    @staticmethod
    def _assessment_confidence(
        techniques, lolbins, malware_tags
    ) -> float:
        if not (techniques or lolbins or malware_tags):
            return 0.0
        corroboration = (
            len(techniques) + len(lolbins) + len(malware_tags)
        )
        diversity = sum(
            bool(group)
            for group in (techniques, lolbins, malware_tags)
        )
        strongest = max(
            [item.confidence for item in techniques]
            + [item.confidence for item in lolbins]
            + [item.confidence for item in malware_tags],
            default=0.0,
        )
        # Anchored to the strongest single finding; corroboration and
        # source diversity add bounded increments so the value cannot
        # exceed what any individual finding supports by much. A single
        # weak finding stays below 0.5.
        return round(
            min(
                0.98,
                strongest * 0.7
                + min(0.15, corroboration * 0.02)
                + min(0.09, diversity * 0.03),
            ),
            2,
        )

    @staticmethod
    def _relationships(
        techniques, lolbins, malware_tags
    ) -> List[Dict[str, Any]]:
        relationships: List[Dict[str, Any]] = []
        for technique in techniques:
            node_ids = {
                item.get("node_id")
                for item in technique.evidence
                if item.get("node_id") is not None
            }
            for item in technique.evidence:
                node_ids.update(item.get("node_ids") or [])
            for node_id in sorted(node_ids, key=str):
                relationships.append(
                    {
                        "source": {
                            "type": "node",
                            "id": node_id,
                        },
                        "target": {
                            "type": "attack-technique",
                            "id": technique.technique_id,
                        },
                        "relationship": "supports",
                        "score": round(
                            technique.confidence, 2
                        ),
                    }
                )

        for item in lolbins:
            for node_id in item.node_ids:
                relationships.append(
                    {
                        "source": {
                            "type": "node",
                            "id": node_id,
                        },
                        "target": {
                            "type": "lolbin",
                            "id": item.executable,
                        },
                        "relationship": "contains",
                        "score": round(item.confidence, 2),
                    }
                )

        for item in malware_tags:
            for node_id in item.node_ids:
                relationships.append(
                    {
                        "source": {
                            "type": "node",
                            "id": node_id,
                        },
                        "target": {
                            "type": "malware-tag",
                            "id": item.tag,
                        },
                        "relationship": "supports",
                        "score": round(item.confidence, 2),
                    }
                )

        return sorted(
            relationships,
            key=lambda item: (
                str(item["source"]["id"]),
                str(item["target"]["type"]),
                str(item["target"]["id"]),
            ),
        )

    @staticmethod
    def _summary(
        techniques, lolbins, malware_tags
    ) -> str:
        if not (techniques or lolbins or malware_tags):
            return (
                "No deterministic threat-intelligence "
                "mappings were produced."
            )
        parts = []
        if techniques:
            parts.append(
                f"{len(techniques)} ATT&CK technique(s)"
            )
        if lolbins:
            parts.append(f"{len(lolbins)} LOLBin(s)")
        if malware_tags:
            parts.append(
                f"{len(malware_tags)} behavioral malware tag(s)"
            )
        return "Identified " + ", ".join(parts) + "."
