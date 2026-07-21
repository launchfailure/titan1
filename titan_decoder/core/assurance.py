"""Fail-closed assurance verdicts for completed Titan reports.

The assurance layer does not claim that bytes are absolutely safe. It records
which security controls actually ran and only emits ``NO_MALICIOUS_EVIDENCE``
when every applicable control passed. Missing providers remain visible as
``unavailable`` and force an ``INDETERMINATE`` verdict.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Mapping, MutableMapping, Sequence


ASSURANCE_VERSION = "1.0"


class AssuranceEngine:
    """Build a deterministic six-control assurance assessment."""

    def __init__(self, config: Mapping[str, Any] | None = None):
        self.config = dict(config or {})

    def run_static_checks(
        self,
        report: MutableMapping[str, Any],
        artifact_payloads: Sequence[tuple[int, bytes]] | None = None,
        iocs: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Run Titan's offline rules, IOC, risk, and intelligence checks.

        Existing plugin or CLI detections are retained and deduplicated by rule
        identifier. This method performs no network access and executes no
        payload content.
        """
        from .detection_rules import CorrelationRulesEngine
        from .intelligence import IntelligenceEngine
        from .risk_scoring import RiskScoringEngine

        pack_paths = [
            Path(value)
            for value in self.config.get("detection_rule_packs", []) or []
            if value
        ]
        rules = CorrelationRulesEngine(pack_paths)
        effective_iocs = iocs
        if effective_iocs is None:
            value = report.get("iocs")
            effective_iocs = value if isinstance(value, dict) else {}
        builtin = rules.evaluate_all(report, effective_iocs)
        existing = report.get("detections")
        detections = self._merge_detections(
            existing if isinstance(existing, list) else [], builtin
        )
        risk = RiskScoringEngine().compute_risk_score(
            report, effective_iocs, detections
        )
        payloads = list(artifact_payloads or [])
        extracted_strings = self._extract_strings(payloads)
        existing_strings = report.get("interesting_strings")
        existing_strings = (
            existing_strings if isinstance(existing_strings, list) else []
        )
        report["interesting_strings"] = sorted(
            {str(value) for value in [*existing_strings, *extracted_strings]}
        )[:500]
        yara_scan = self._scan_yara(payloads)

        report["detections"] = detections
        report["risk_assessment"] = risk
        report["intelligence"] = IntelligenceEngine().analyze(
            report,
            iocs=effective_iocs,
            detections=detections,
            risk=risk,
        )
        report["static_analysis"] = {
            "completed": True,
            "offline": True,
            "providers": [
                "content_hashing",
                "file_structure_parsers",
                "ioc_extraction",
                "titan_builtin_rules",
                "active_content_patterns",
            ],
            "rules_evaluated": len(rules.rules),
            "rule_packs": rules.rule_packs,
            "detection_count": len(detections),
            "strings_extracted": len(report["interesting_strings"]),
            "yara": yara_scan,
        }
        return report["static_analysis"]

    def evaluate(self, report: Mapping[str, Any]) -> dict[str, Any]:
        """Evaluate all six assurance controls and return the final verdict."""
        outcome = report.get("analysis_outcome")
        outcome = outcome if isinstance(outcome, Mapping) else {}
        root_hash = self._root_hash(report)
        controls = [
            self._decoding_control(outcome),
            self._format_control(report, outcome),
            self._opaque_control(outcome),
            self._static_control(report, root_hash),
            self._dynamic_control(report, root_hash),
            self._provenance_control(root_hash),
        ]

        dispositions = {
            str(control.get("disposition") or "") for control in controls
        }
        if "malicious" in dispositions:
            verdict = "MALICIOUS"
            summary = "A high-confidence malicious indicator was confirmed."
            confidence = 1.0
        elif "suspicious" in dispositions:
            verdict = "SUSPICIOUS"
            summary = "One or more security controls found suspicious evidence."
            confidence = 0.8
        elif all(
            control["state"] in {"pass", "not_applicable"}
            for control in controls
        ):
            verdict = "NO_MALICIOUS_EVIDENCE"
            summary = (
                "Every applicable assurance control completed without finding "
                "malicious evidence. This is not a guarantee of safety."
            )
            confidence = 0.95
        else:
            verdict = "INDETERMINATE"
            summary = (
                "The payload cannot receive a benign assessment because one or "
                "more required controls failed or were unavailable."
            )
            confidence = 0.0

        blockers = [
            {
                "control_id": control["id"],
                "state": control["state"],
                "summary": control["summary"],
            }
            for control in controls
            if control["state"] in {"fail", "unavailable"}
        ]
        satisfied = sum(
            control["state"] in {"pass", "not_applicable"}
            for control in controls
        )
        return {
            "version": ASSURANCE_VERSION,
            "verdict": verdict,
            "confidence": confidence,
            "summary": summary,
            "root_sha256": root_hash,
            "controls_satisfied": satisfied,
            "controls_total": len(controls),
            "all_required_controls_passed": not blockers,
            "controls": controls,
            "blockers": blockers,
            "safety_claim": "No analysis can prove absolute safety.",
        }

    @staticmethod
    def _control(
        control_id: str,
        label: str,
        state: str,
        summary: str,
        evidence: Any = None,
        disposition: str | None = None,
    ) -> dict[str, Any]:
        value: dict[str, Any] = {
            "id": control_id,
            "label": label,
            "state": state,
            "summary": summary,
        }
        if evidence not in (None, [], {}, ""):
            value["evidence"] = evidence
        if disposition:
            value["disposition"] = disposition
        return value

    def _decoding_control(self, outcome: Mapping[str, Any]) -> dict[str, Any]:
        if bool(outcome.get("complete")):
            return self._control(
                "complete_decoding",
                "Complete decoding",
                "pass",
                "All decode branches reached recognized or readable endpoints.",
                outcome.get("terminal_node_ids") or [],
            )
        status = str(outcome.get("status") or "missing")
        return self._control(
            "complete_decoding",
            "Complete decoding",
            "fail" if outcome else "unavailable",
            f"Analysis coverage is incomplete ({status}).",
            outcome.get("limitations") or [],
        )

    def _format_control(
        self, report: Mapping[str, Any], outcome: Mapping[str, Any]
    ) -> dict[str, Any]:
        if not outcome:
            return self._control(
                "format_validation",
                "Format and structure validation",
                "unavailable",
                "No analysis outcome was available for structural validation.",
            )
        opaque = outcome.get("opaque_terminal_node_ids") or []
        terminal_ids = set(outcome.get("terminal_node_ids") or [])
        nodes = report.get("nodes") if isinstance(report.get("nodes"), list) else []
        terminals = [
            node
            for node in nodes
            if isinstance(node, Mapping) and node.get("id") in terminal_ids
        ]
        invalid = [
            node.get("id")
            for node in terminals
            if str(node.get("content_type") or "").lower() not in {"text"}
        ]
        if bool(outcome.get("complete")) and not opaque and not invalid:
            return self._control(
                "format_validation",
                "Format and structure validation",
                "pass",
                "Terminal artifacts are readable or were produced by validated parsers.",
                [node.get("id") for node in terminals],
            )
        return self._control(
            "format_validation",
            "Format and structure validation",
            "fail",
            "One or more terminal artifacts have an unknown or unvalidated format.",
            sorted(set(opaque) | set(invalid)),
        )

    def _opaque_control(self, outcome: Mapping[str, Any]) -> dict[str, Any]:
        if not outcome:
            return self._control(
                "no_opaque_payloads",
                "No opaque terminal payloads",
                "unavailable",
                "Opaque-payload coverage was not reported.",
            )
        opaque = list(outcome.get("opaque_terminal_node_ids") or [])
        if not opaque:
            return self._control(
                "no_opaque_payloads",
                "No opaque terminal payloads",
                "pass",
                "No opaque terminal payload remains.",
            )
        return self._control(
            "no_opaque_payloads",
            "No opaque terminal payloads",
            "fail",
            f"{len(opaque)} opaque terminal payload(s) remain.",
            opaque,
        )

    def _static_control(
        self, report: Mapping[str, Any], root_hash: str | None
    ) -> dict[str, Any]:
        reputation = self._hash_list_match(
            root_hash, self.config.get("malicious_hashes_path")
        )
        if reputation:
            return self._control(
                "static_analysis",
                "Static signatures and content analysis",
                "fail",
                "The root hash matched the configured malicious hash list.",
                reputation,
                disposition="malicious",
            )

        static = report.get("static_analysis")
        if not isinstance(static, Mapping) or not static.get("completed"):
            return self._control(
                "static_analysis",
                "Static signatures and content analysis",
                "unavailable",
                "The offline static-analysis suite did not complete.",
            )

        yara = static.get("yara")
        yara = yara if isinstance(yara, Mapping) else {}
        if yara.get("state") == "unavailable":
            return self._control(
                "static_analysis",
                "Static signatures and content analysis",
                "unavailable",
                "YARA was requested but its rules or scanner were unavailable.",
                yara.get("reason"),
            )
        yara_matches = yara.get("matches")
        yara_matches = yara_matches if isinstance(yara_matches, list) else []
        if yara_matches:
            return self._control(
                "static_analysis",
                "Static signatures and content analysis",
                "fail",
                f"YARA matched {len(yara_matches)} artifact signature(s).",
                yara_matches[:10],
                disposition="suspicious",
            )

        detections = report.get("detections")
        detections = detections if isinstance(detections, list) else []
        if detections:
            return self._control(
                "static_analysis",
                "Static signatures and content analysis",
                "fail",
                f"Static analysis produced {len(detections)} detection(s).",
                [
                    item.get("rule_id") or item.get("id") or item.get("name")
                    for item in detections[:10]
                    if isinstance(item, Mapping)
                ],
                disposition="suspicious",
            )
        intelligence = report.get("intelligence")
        intelligence = intelligence if isinstance(intelligence, Mapping) else {}
        signals = intelligence.get("signals")
        signals = signals if isinstance(signals, list) else []
        if signals:
            return self._control(
                "static_analysis",
                "Static signatures and content analysis",
                "fail",
                f"Static analysis produced {len(signals)} risk signal(s).",
                [
                    item.get("code")
                    for item in signals[:10]
                    if isinstance(item, Mapping)
                ],
                disposition="suspicious",
            )
        return self._control(
            "static_analysis",
            "Static signatures and content analysis",
            "pass",
            "Offline signatures, rules, strings, IOCs, and active-content checks completed without a detection.",
            static.get("providers") or [],
        )

    def _dynamic_control(
        self, report: Mapping[str, Any], root_hash: str | None
    ) -> dict[str, Any]:
        if not self._requires_dynamic_analysis(report):
            return self._control(
                "dynamic_vm_analysis",
                "Isolated VM behavior analysis",
                "not_applicable",
                "No executable or active-content artifact was recognized.",
            )
        attestation = self._load_hash_attestation(
            self.config.get("sandbox_attestations_dir"), root_hash
        )
        if not attestation:
            return self._control(
                "dynamic_vm_analysis",
                "Isolated VM behavior analysis",
                "unavailable",
                "Executable or active content requires a hash-bound VM attestation.",
            )
        verdict = str(attestation.get("verdict") or "").lower()
        isolation = str(attestation.get("isolation") or "").lower()
        completed = bool(attestation.get("completed"))
        if not completed or isolation not in {"vm", "virtual_machine"}:
            return self._control(
                "dynamic_vm_analysis",
                "Isolated VM behavior analysis",
                "unavailable",
                "The sandbox attestation is incomplete or was not produced by a VM.",
            )
        if verdict == "malicious":
            return self._control(
                "dynamic_vm_analysis",
                "Isolated VM behavior analysis",
                "fail",
                "The VM observed malicious behavior.",
                attestation,
                disposition="malicious",
            )
        if verdict == "suspicious":
            return self._control(
                "dynamic_vm_analysis",
                "Isolated VM behavior analysis",
                "fail",
                "The VM observed suspicious behavior.",
                attestation,
                disposition="suspicious",
            )
        if verdict in {"clean", "no_malicious_behavior"}:
            return self._control(
                "dynamic_vm_analysis",
                "Isolated VM behavior analysis",
                "pass",
                "The configured VM completed without observing malicious behavior.",
                attestation,
            )
        return self._control(
            "dynamic_vm_analysis",
            "Isolated VM behavior analysis",
            "unavailable",
            "The VM attestation did not contain a recognized verdict.",
        )

    def _provenance_control(self, root_hash: str | None) -> dict[str, Any]:
        allowlist = self._hash_list_match(
            root_hash, self.config.get("trusted_hashes_path")
        )
        if allowlist:
            return self._control(
                "trusted_provenance",
                "Trusted provenance",
                "pass",
                "The root hash is present in the configured trusted hash store.",
                allowlist,
            )
        attestation = self._load_hash_attestation(
            self.config.get("provenance_attestations_dir"), root_hash
        )
        if attestation and attestation.get("trusted") is True:
            method = str(attestation.get("verification_method") or "").strip()
            identity = str(attestation.get("identity") or "").strip()
            if method and identity:
                return self._control(
                    "trusted_provenance",
                    "Trusted provenance",
                    "pass",
                    "A hash-bound provenance attestation verified the source identity.",
                    attestation,
                )
        return self._control(
            "trusted_provenance",
            "Trusted provenance",
            "unavailable",
            "No trusted hash, signature, or source attestation was available.",
        )

    @staticmethod
    def _merge_detections(
        existing: Sequence[Any], builtin: Sequence[Any]
    ) -> list[dict[str, Any]]:
        merged: list[dict[str, Any]] = []
        seen: set[str] = set()
        for item in [*existing, *builtin]:
            if not isinstance(item, Mapping):
                continue
            value = dict(item)
            identity = str(
                value.get("rule_id") or value.get("id") or value.get("name") or value
            )
            if identity in seen:
                continue
            seen.add(identity)
            merged.append(value)
        return merged

    @staticmethod
    def _extract_strings(payloads: Sequence[tuple[int, bytes]]) -> list[str]:
        values: set[str] = set()
        for _, data in payloads[:300]:
            for match in re.finditer(rb"[\x20-\x7e]{6,}", data[:2_000_000]):
                values.add(match.group(0)[:300].decode("ascii", errors="ignore"))
                if len(values) >= 500:
                    return sorted(values)
        return sorted(values)

    def _scan_yara(self, payloads: Sequence[tuple[int, bytes]]) -> dict[str, Any]:
        if not self.config.get("enable_yara", False):
            return {"state": "not_configured", "matches": []}
        rules_path = self.config.get("yara_rules_path")
        if not rules_path or not Path(str(rules_path)).expanduser().is_file():
            return {
                "state": "unavailable",
                "matches": [],
                "reason": "configured YARA rules file was not found",
            }
        if not payloads:
            return {
                "state": "unavailable",
                "matches": [],
                "reason": "raw artifact payloads were not supplied to the scanner",
            }
        try:
            import yara
        except ImportError:
            return {
                "state": "unavailable",
                "matches": [],
                "reason": "yara-python is not installed",
            }
        try:
            rules = yara.compile(filepath=str(Path(str(rules_path)).expanduser()))
            matches: list[dict[str, Any]] = []
            for node_id, data in payloads[:300]:
                for match in rules.match(data=data, timeout=10):
                    matches.append(
                        {
                            "node_id": node_id,
                            "rule": str(match.rule),
                            "tags": [str(tag) for tag in match.tags],
                        }
                    )
                    if len(matches) >= 100:
                        break
                if len(matches) >= 100:
                    break
            return {"state": "completed", "matches": matches}
        except Exception as exc:
            return {
                "state": "unavailable",
                "matches": [],
                "reason": f"YARA scan failed: {type(exc).__name__}",
            }

    @staticmethod
    def _root_hash(report: Mapping[str, Any]) -> str | None:
        nodes = report.get("nodes")
        if not isinstance(nodes, list):
            return None
        roots = [
            node
            for node in nodes
            if isinstance(node, Mapping) and node.get("parent") is None
        ]
        if not roots:
            return None
        value = str(roots[0].get("sha256") or "").lower()
        return value if len(value) == 64 else None

    @staticmethod
    def _requires_dynamic_analysis(report: Mapping[str, Any]) -> bool:
        nodes = report.get("nodes")
        if not isinstance(nodes, list):
            return False
        active_markers = (
            "powershell",
            "cmd.exe",
            "wscript",
            "cscript",
            "javascript:",
            "vbscript:",
        )
        for node in nodes:
            if not isinstance(node, Mapping):
                continue
            method = str(node.get("method") or "").upper()
            preview = str(node.get("content_preview") or "")
            if method in {"ANALYZE_PE", "ANALYZE_ELF"}:
                return True
            if preview.startswith(("MZ", "\x7fELF")):
                return True
            lowered = preview.lower()
            if any(marker in lowered for marker in active_markers):
                return True
        return False

    @staticmethod
    def _hash_list_match(root_hash: str | None, configured_path: Any) -> dict[str, Any] | None:
        if not root_hash or not configured_path:
            return None
        path = Path(str(configured_path)).expanduser()
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError):
            return None
        for line_number, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            digest, _, label = stripped.partition(" ")
            if digest.lower() == root_hash:
                return {
                    "path": str(path),
                    "line": line_number,
                    "label": label.strip() or None,
                }
        return None

    @staticmethod
    def _load_hash_attestation(
        configured_dir: Any, root_hash: str | None
    ) -> dict[str, Any] | None:
        if not configured_dir or not root_hash:
            return None
        path = Path(str(configured_dir)).expanduser() / f"{root_hash}.json"
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            return None
        if not isinstance(value, dict):
            return None
        claimed = str(value.get("sample_sha256") or "").lower()
        if claimed != root_hash or str(value.get("schema_version") or "") != "1.0":
            return None
        return value
