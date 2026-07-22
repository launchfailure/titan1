"""Deterministic, bounded YARA scanning over every artifact-graph node.

YARA support is an optional dependency (``yara-python``). The scanner is
fail-closed and explicit about its state: when YARA was requested but the
library or the configured rules are unavailable, the result says so instead
of silently scanning nothing. Scanning covers every node payload in graph
order — including decoded and extracted content — so signatures match
content that a scan of the raw input alone would never see.

Every output is deterministic: rule files load in sorted order, one
namespace per file, matches are reported in (node order, namespace, rule)
order, and all captured data (tags, meta, matched strings) is bounded and
sorted.
"""

from __future__ import annotations

import logging
from pathlib import Path
import re
from typing import Any, Mapping, Sequence

logger = logging.getLogger(__name__)

_RULE_SUFFIXES = (".yar", ".yara")
_NAMESPACE_SAFE = re.compile(r"[^A-Za-z0-9_.-]+")


def yara_available() -> bool:
    """Return True when the optional yara-python dependency is importable."""
    try:
        import yara  # noqa: F401
    except ImportError:
        return False
    return True


def _namespace_for(path: Path) -> str:
    return _NAMESPACE_SAFE.sub("_", path.stem)[:100] or "rules"


def _severity_from_meta(meta: Mapping[str, Any]) -> str:
    value = str(meta.get("severity", "")).lower()
    return value if value in {"low", "medium", "high", "critical"} else "medium"


class YaraScanner:
    """Compile configured YARA rules and scan node payloads with bounds."""

    def __init__(self, config: Mapping[str, Any]):
        self.enabled = bool(config.get("enable_yara", False))
        self.rules_path = config.get("yara_rules_path")
        self.rules_files = list(config.get("yara_rules_files") or [])
        self.rules_dirs = list(config.get("yara_rules_dirs") or [])
        self.timeout_seconds = max(1, int(config.get("yara_timeout_seconds", 10)))
        self.max_matches = max(1, int(config.get("yara_max_matches", 200)))
        self.max_nodes = max(1, int(config.get("yara_max_nodes", 300)))
        self.max_meta_bytes = max(64, int(config.get("yara_max_meta_bytes", 4096)))
        self.max_strings_per_match = max(
            0, int(config.get("yara_max_strings_per_match", 8))
        )
        self.max_string_bytes = max(8, int(config.get("yara_max_string_bytes", 128)))
        self._rules: Any = None
        self._sources: list[str] = []
        self._load_error: str | None = None
        self._loaded = False

    # -- rule loading ----------------------------------------------------

    def _rule_files(self) -> list[Path]:
        """Resolve configured sources to a sorted, de-duplicated file list."""
        files: list[Path] = []
        single_files = [self.rules_path] if self.rules_path else []
        for value in (*single_files, *self.rules_files):
            candidate = Path(str(value)).expanduser()
            if not candidate.is_file():
                raise FileNotFoundError(
                    f"configured YARA rules file was not found: {candidate}"
                )
            files.append(candidate)
        for value in self.rules_dirs:
            directory = Path(str(value)).expanduser()
            if not directory.is_dir():
                raise FileNotFoundError(
                    f"configured YARA rules directory was not found: {directory}"
                )
            found = [
                path
                for path in directory.iterdir()
                if path.is_file() and path.suffix.lower() in _RULE_SUFFIXES
            ]
            if not found:
                raise FileNotFoundError(
                    f"YARA rules directory contains no .yar/.yara files: {directory}"
                )
            files.extend(found)
        unique = sorted(
            {path.resolve() for path in files},
            key=lambda path: path.as_posix().casefold(),
        )
        if not unique:
            raise FileNotFoundError("no YARA rules were configured")
        return unique

    def load(self) -> None:
        """Compile all configured rule files, one namespace per file."""
        if self._loaded:
            return
        self._loaded = True
        if not self.enabled:
            return
        try:
            import yara
        except ImportError:
            self._load_error = "yara-python is not installed"
            return
        try:
            files = self._rule_files()
            filepaths: dict[str, str] = {}
            for path in files:
                namespace = _namespace_for(path)
                index = 2
                while namespace in filepaths:
                    namespace = f"{_namespace_for(path)}_{index}"
                    index += 1
                filepaths[namespace] = str(path)
            self._rules = yara.compile(filepaths=filepaths)
            self._sources = sorted(filepaths.values(), key=str.casefold)
        except yara.Error as exc:
            self._load_error = f"YARA rule compilation failed: {exc}"[:1000]
        except (OSError, ValueError) as exc:
            self._load_error = str(exc)[:1000]

    # -- scanning --------------------------------------------------------

    def _capture_strings(self, match: Any) -> list[dict[str, Any]]:
        captured: list[dict[str, Any]] = []
        for string in list(getattr(match, "strings", ()))[: self.max_strings_per_match]:
            instances = list(getattr(string, "instances", ()))[:1]
            snippet = ""
            offset = None
            if instances:
                raw = bytes(instances[0].matched_data)[: self.max_string_bytes]
                snippet = raw.decode("ascii", errors="backslashreplace")
                offset = int(instances[0].offset)
            captured.append(
                {
                    "identifier": str(string.identifier),
                    "offset": offset,
                    "data": snippet,
                }
            )
        return sorted(captured, key=lambda item: str(item["identifier"]))

    def _capture_meta(self, match: Any) -> dict[str, Any]:
        meta: dict[str, Any] = {}
        budget = self.max_meta_bytes
        for key in sorted(getattr(match, "meta", {}) or {}):
            value = match.meta[key]
            if not isinstance(value, (bool, int)):
                value = str(value)[:512]
            cost = len(str(key)) + len(str(value))
            if cost > budget:
                break
            budget -= cost
            meta[str(key)] = value
        return meta

    def scan(self, payloads: Sequence[tuple[int, bytes]]) -> dict[str, Any]:
        """Scan node payloads and return a deterministic result envelope."""
        if not self.enabled:
            return {"state": "not_configured", "matches": []}
        self.load()
        if self._load_error is not None:
            return {
                "state": "unavailable",
                "matches": [],
                "reason": self._load_error,
            }
        if self._rules is None:
            return {
                "state": "unavailable",
                "matches": [],
                "reason": "YARA rules were not loaded",
            }
        if not payloads:
            return {
                "state": "unavailable",
                "matches": [],
                "reason": "raw artifact payloads were not supplied to the scanner",
            }
        import yara

        matches: list[dict[str, Any]] = []
        scanned = 0
        errors = 0
        truncated = False
        for node_id, data in payloads[: self.max_nodes]:
            if not isinstance(data, bytes) or not data:
                continue
            scanned += 1
            try:
                found = self._rules.match(data=data, timeout=self.timeout_seconds)
            except yara.TimeoutError:
                errors += 1
                continue
            except yara.Error:
                errors += 1
                continue
            for match in sorted(
                found, key=lambda item: (str(item.namespace), str(item.rule))
            ):
                meta = self._capture_meta(match)
                matches.append(
                    {
                        "node_id": int(node_id),
                        "namespace": str(match.namespace),
                        "rule": str(match.rule),
                        "tags": sorted(str(tag) for tag in match.tags),
                        "meta": meta,
                        "severity": _severity_from_meta(meta),
                        "strings": self._capture_strings(match),
                    }
                )
                if len(matches) >= self.max_matches:
                    truncated = True
                    break
            if truncated:
                break
        return {
            "state": "completed",
            "rules_sources": list(self._sources),
            "scanned_nodes": scanned,
            "scan_errors": errors,
            "match_limit_reached": truncated,
            "matches": matches,
        }


def yara_matches_to_detections(
    scan_result: Mapping[str, Any],
) -> list[dict[str, Any]]:
    """Convert scan matches into detection entries for the detection stage.

    Matches of the same rule across several nodes collapse into one detection
    carrying every matched node id, so risk scoring weighs distinct
    signatures rather than repetition of one signature.
    """
    matches = scan_result.get("matches")
    if scan_result.get("state") != "completed" or not isinstance(matches, list):
        return []
    grouped: dict[str, dict[str, Any]] = {}
    for match in matches:
        if not isinstance(match, Mapping):
            continue
        namespace = str(match.get("namespace") or "rules")
        rule = str(match.get("rule") or "")
        if not rule:
            continue
        rule_id = f"YARA:{namespace}:{rule}"
        raw_meta = match.get("meta")
        meta: Mapping[str, Any] = raw_meta if isinstance(raw_meta, Mapping) else {}
        entry = grouped.setdefault(
            rule_id,
            {
                "rule_id": rule_id,
                "name": str(meta.get("description") or rule)[:200],
                "description": str(meta.get("description") or "")[:1000],
                "severity": str(match.get("severity") or "medium"),
                "attack_ids": [],
                "node_ids": [],
                "source": {"type": "yara", "namespace": namespace, "rule": rule},
            },
        )
        node_id = match.get("node_id")
        if isinstance(node_id, int) and node_id not in entry["node_ids"]:
            entry["node_ids"].append(node_id)
        attack_id = str(meta.get("attack_id") or "")
        if attack_id and attack_id not in entry["attack_ids"]:
            entry["attack_ids"].append(attack_id)
    for entry in grouped.values():
        entry["node_ids"].sort()
        entry["attack_ids"].sort()
    return [grouped[key] for key in sorted(grouped)]
