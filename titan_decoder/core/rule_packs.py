"""Detection rule packs (rules-as-data).

Rule packs let users extend detections without shipping new code.

Format (JSON or YAML):

schema_version: 1
pack:
  name: "Example Pack"
  version: "0.1.0"
rules:
  - id: "EX-001"
    name: "Contains powershell"
    description: "Detects PowerShell strings"
    severity: "medium"
    type: "content_regex"
    pattern: "powershell"
    flags: ["IGNORECASE"]
    attack_ids: ["T1059.001"]

Supported rule types:
- content_regex: regex over concatenated node content_preview
- ioc_present: requires one or more IOC types to meet minimum counts

Optional per-rule metadata:
- attack_ids: MITRE ATT&CK technique IDs the rule indicates. Carried on
  triggered detections and consumed by the Threat Intelligence Engine as
  corroborating evidence (IDs must exist in the bundled ATT&CK catalog to be
  reported there).

Validation and limits
---------------------
Rule definitions are validated (``validate_rule_def``) both at load time —
the engine skips invalid or duplicate rules with a logged warning — and by
``titan-decoder --rules-validate``, which reports every problem per rule and
exits non-zero. Enforced constraints:

- at most ``MAX_RULES_PER_PACK`` rules per pack (the whole pack is rejected
  beyond that — each ``content_regex`` costs bounded-but-real evaluation
  time, so an unbounded pack is a resource-exhaustion vector);
- rule ``id`` is required, at most ``MAX_ID_LENGTH`` characters, and must not
  use the reserved ``TITAN-`` prefix (built-in rules own it; a pack rule
  cannot impersonate one);
- duplicate ids are rejected — within a pack, across packs, and against
  built-in rules (first definition wins at load time);
- ``content_regex`` patterns must be non-empty, compile, and stay within
  ``MAX_PATTERN_LENGTH``; ``flags`` may only name IGNORECASE, MULTILINE,
  DOTALL;
- ``ioc_present`` requires a non-empty ``ioc_types`` list of at most
  ``MAX_IOC_TYPES_PER_RULE`` strings and an integer ``min_each`` in
  ``[1, MAX_MIN_EACH]``;
- ``severity``, when present, must be low/medium/high/critical;
- ``attack_ids``, when present, must be at most ``MAX_ATTACK_IDS_PER_RULE``
  well-formed technique IDs (``T1234`` / ``T1234.001``).

Security note
-------------
A ``content_regex`` pattern is supplied by whoever authors the rule pack and is
run against content derived from the analyzed (untrusted) payload. ``re`` has no
execution timeout and a tight C match loop cannot be interrupted by signals, so
a pattern prone to catastrophic backtracking (e.g. ``(a+)+$``, ``(.*a){20}``)
would otherwise hang the run when the payload contains a triggering string.

This is now *defended*, not merely documented: ``content_regex_search`` runs the
match under linear-time RE2 (``google-re2``) when installed, and otherwise in a
separate process guarded by a hard wall-clock timeout — a process can be killed
even mid-backtrack, unlike a thread. On timeout the rule is treated as "no
match" and a warning is logged. You should still prefer trusted packs and
well-formed patterns, but a hostile pattern can no longer hang the engine.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional
import json
import logging
import multiprocessing as mp
import re

logger = logging.getLogger(__name__)

# Hard wall-clock limit for evaluating a single pack-supplied content_regex.
# A catastrophic-backtracking pattern cannot be interrupted by signals inside
# re's C match loop, so the bound is enforced by running the match in a separate
# process that can be terminated.
CONTENT_REGEX_TIMEOUT_SECONDS = 2.0

# Validation limits (see the module docstring). Each content_regex evaluation
# has a bounded but real cost, so the per-pack rule cap is the primary
# resource-exhaustion guard; the rest keep individual definitions sane.
MAX_RULES_PER_PACK = 200
MAX_ID_LENGTH = 64
MAX_PATTERN_LENGTH = 2048
MAX_IOC_TYPES_PER_RULE = 16
MAX_MIN_EACH = 10_000
MAX_ATTACK_IDS_PER_RULE = 16

# Built-in rules own this prefix; pack rules must not impersonate them.
RESERVED_ID_PREFIX = "TITAN-"

_ALLOWED_TYPES = frozenset({"content_regex", "ioc_present"})
_ALLOWED_FLAGS = frozenset({"IGNORECASE", "MULTILINE", "DOTALL"})
_ALLOWED_SEVERITIES = frozenset({"low", "medium", "high", "critical"})
_ATTACK_ID_PATTERN = re.compile(r"^T\d{4}(?:\.\d{3})?$")


@dataclass(frozen=True)
class RulePackInfo:
    name: str
    version: str
    schema_version: int
    path: str


class RulePackError(ValueError):
    pass


def load_rule_pack(path: Path) -> tuple[RulePackInfo, List[Dict[str, Any]]]:
    """Load a rule pack file (JSON or YAML)."""
    if not path.exists():
        raise RulePackError(f"Rule pack not found: {path}")

    raw: Dict[str, Any]
    suffix = path.suffix.lower()
    if suffix in {".json"}:
        raw = json.loads(path.read_text())
    elif suffix in {".yml", ".yaml"}:
        try:
            import yaml  # type: ignore
        except Exception as e:
            raise RulePackError(
                "YAML rule pack requires PyYAML (install via requirements-optional.txt)"
            ) from e
        raw = yaml.safe_load(path.read_text())
        if raw is None:
            raw = {}
    else:
        raise RulePackError(f"Unsupported rule pack type: {suffix}")

    if not isinstance(raw, dict):
        raise RulePackError("Rule pack root must be an object")

    schema_version = raw.get("schema_version", 1)
    if schema_version != 1:
        raise RulePackError(f"Unsupported rule pack schema_version: {schema_version}")

    pack = raw.get("pack") or {}
    if not isinstance(pack, dict):
        raise RulePackError("pack must be an object")

    name = str(pack.get("name") or "Unnamed Pack")
    version = str(pack.get("version") or "0.0.0")
    rules = raw.get("rules") or []
    if not isinstance(rules, list):
        raise RulePackError("rules must be an array")
    if len(rules) > MAX_RULES_PER_PACK:
        raise RulePackError(
            f"pack declares {len(rules)} rules, exceeding the limit of "
            f"{MAX_RULES_PER_PACK}"
        )

    return RulePackInfo(
        name=name, version=version, schema_version=schema_version, path=str(path)
    ), rules


def validate_rule_def(rule_def: Any) -> List[str]:
    """Validate a single rule definition; return a list of problems.

    Used both by the engine at load time (invalid rules are skipped with a
    warning) and by ``--rules-validate`` (problems are reported per rule and
    the command exits non-zero).
    """
    if not isinstance(rule_def, dict):
        return ["rule must be an object"]
    problems: List[str] = []

    rid = rule_def.get("id")
    if not isinstance(rid, str) or not rid.strip():
        problems.append("missing or empty 'id'")
    elif len(rid) > MAX_ID_LENGTH:
        problems.append(f"'id' exceeds {MAX_ID_LENGTH} characters")
    elif rid.upper().startswith(RESERVED_ID_PREFIX):
        problems.append(
            f"'{RESERVED_ID_PREFIX}' id prefix is reserved for built-in rules"
        )

    rtype = (rule_def.get("type") or "").strip()
    if rtype not in _ALLOWED_TYPES:
        problems.append(
            f"unknown rule type {rtype!r} (expected one of {sorted(_ALLOWED_TYPES)})"
        )

    flags = rule_def.get("flags")
    if flags is not None:
        if not isinstance(flags, list):
            problems.append("'flags' must be an array")
            flags = None
        else:
            unknown = [
                f
                for f in flags
                if not isinstance(f, str) or f.upper() not in _ALLOWED_FLAGS
            ]
            if unknown:
                problems.append(
                    f"unknown flags {unknown!r} (expected {sorted(_ALLOWED_FLAGS)})"
                )

    if rtype == "content_regex":
        pattern = rule_def.get("pattern")
        if not isinstance(pattern, str) or not pattern:
            problems.append("content_regex requires a non-empty 'pattern'")
        elif len(pattern) > MAX_PATTERN_LENGTH:
            problems.append(f"'pattern' exceeds {MAX_PATTERN_LENGTH} characters")
        else:
            try:
                re.compile(pattern, _resolve_flags(flags))
            except re.error as e:
                problems.append(f"invalid regex pattern: {e}")

    if rtype == "ioc_present":
        ioc_types = rule_def.get("ioc_types")
        if (
            not isinstance(ioc_types, list)
            or not ioc_types
            or not all(isinstance(t, str) and t for t in ioc_types)
        ):
            problems.append(
                "ioc_present requires a non-empty 'ioc_types' array of strings"
            )
        elif len(ioc_types) > MAX_IOC_TYPES_PER_RULE:
            problems.append(f"'ioc_types' exceeds {MAX_IOC_TYPES_PER_RULE} entries")
        min_each = rule_def.get("min_each", 1)
        if (
            not isinstance(min_each, int)
            or isinstance(min_each, bool)
            or not 1 <= min_each <= MAX_MIN_EACH
        ):
            problems.append(f"'min_each' must be an integer in [1, {MAX_MIN_EACH}]")

    severity = rule_def.get("severity")
    if severity is not None and (
        not isinstance(severity, str) or severity.lower() not in _ALLOWED_SEVERITIES
    ):
        problems.append(
            f"unknown severity {severity!r} (expected {sorted(_ALLOWED_SEVERITIES)})"
        )

    attack_ids = rule_def.get("attack_ids")
    if attack_ids is not None:
        if not isinstance(attack_ids, list):
            problems.append("'attack_ids' must be an array")
        elif len(attack_ids) > MAX_ATTACK_IDS_PER_RULE:
            problems.append(f"'attack_ids' exceeds {MAX_ATTACK_IDS_PER_RULE} entries")
        else:
            malformed = [
                t
                for t in attack_ids
                if not isinstance(t, str) or not _ATTACK_ID_PATTERN.match(t)
            ]
            if malformed:
                problems.append(
                    f"malformed attack_ids {malformed!r} (expected "
                    "T1234 or T1234.001 form)"
                )

    return problems


def validate_rule_pack(path: Path) -> Dict[str, Any]:
    """Deep-validate a rule pack; the backing check for --rules-validate.

    Loads the pack (structural errors and the per-pack rule limit surface
    here), then validates every rule definition and checks for duplicate ids
    within the pack. Returns ``{"path", "ok", "errors", ...}``; ``ok`` is
    True only when there are no errors at all.
    """
    result: Dict[str, Any] = {"path": str(path), "ok": False, "errors": []}
    try:
        info, rules = load_rule_pack(Path(path))
    except Exception as e:
        result["errors"].append(str(e))
        return result

    result["name"] = info.name
    result["version"] = info.version
    result["rule_count"] = len(rules)

    seen_ids: set = set()
    for index, rule_def in enumerate(rules):
        rid = rule_def.get("id") if isinstance(rule_def, dict) else None
        label = rid if isinstance(rid, str) and rid else f"rules[{index}]"
        for problem in validate_rule_def(rule_def):
            result["errors"].append(f"{label}: {problem}")
        if isinstance(rid, str) and rid:
            if rid in seen_ids:
                result["errors"].append(f"{label}: duplicate rule id")
            seen_ids.add(rid)

    result["ok"] = not result["errors"]
    return result


def _resolve_flags(flags: Optional[List[str]]) -> int:
    re_flags = 0
    for f in flags or []:
        if f.upper() == "IGNORECASE":
            re_flags |= re.IGNORECASE
        elif f.upper() == "MULTILINE":
            re_flags |= re.MULTILINE
        elif f.upper() == "DOTALL":
            re_flags |= re.DOTALL
    return re_flags


def compile_content_regex(
    pattern: str, flags: Optional[List[str]] = None
) -> re.Pattern:
    return re.compile(pattern, _resolve_flags(flags))


def _regex_worker(pattern: str, re_flags: int, text: str, q) -> None:
    """Run in a child process: search and put the boolean result on the queue."""
    try:
        q.put(bool(re.compile(pattern, re_flags).search(text)))
    except Exception:
        q.put(False)


def content_regex_search(
    pattern: str,
    flags: Optional[List[str]],
    text: str,
    timeout: float = CONTENT_REGEX_TIMEOUT_SECONDS,
) -> bool:
    """Evaluate a pack-supplied ``content_regex`` with a hard time bound.

    Rule-pack patterns are attacker-influenced (see the module security note),
    and ``re`` has no execution timeout — a catastrophic-backtracking pattern
    like ``(a+)+$`` against a triggering payload can hang the whole run. This
    bounds it two ways:

    1. If google-re2 (``re2``) is installed, use it: RE2 is linear-time and
       cannot catastrophically backtrack, so no timeout is even needed. This is
       the preferred, dependency-optional path.
    2. Otherwise run the match in a separate process and terminate it if it
       exceeds ``timeout``. A thread would not work — the match runs in a single
       C call that never yields to let a signal or flag stop it — but a process
       can be killed. On timeout the rule is treated as "no match" and a warning
       is logged.
    """
    re_flags = _resolve_flags(flags)

    # Preferred: linear-time RE2, immune to ReDoS by construction.
    try:
        import re2  # type: ignore

        try:
            return bool(re2.compile(pattern, re_flags).search(text))
        except Exception:
            # re2 rejects some constructs (backreferences/lookaround); fall
            # through to the sandboxed re path rather than silently skipping.
            pass
    except ImportError:
        pass

    # Fallback: run re in a killable subprocess with a hard timeout.
    ctx: Any
    try:
        ctx = mp.get_context("fork")
    except ValueError:  # platforms without fork (e.g. Windows)
        ctx = mp.get_context("spawn")

    q = ctx.Queue()
    proc = ctx.Process(target=_regex_worker, args=(pattern, re_flags, text, q))
    proc.daemon = True
    proc.start()
    proc.join(timeout)
    if proc.is_alive():
        proc.terminate()
        proc.join()
        logger.warning(
            "content_regex evaluation exceeded %.1fs and was terminated "
            "(possible catastrophic backtracking); treating as no match",
            timeout,
        )
        return False
    try:
        # Short blocking get: the child has exited (join returned), but allow a
        # brief moment for the queued result to become readable.
        return bool(q.get(timeout=0.5))
    except Exception:
        return False


def evaluate_pack_rule(
    rule_def: Dict[str, Any], report: Dict[str, Any], iocs: Dict[str, Any]
) -> bool:
    """Evaluate a single pack rule definition."""
    rtype = (rule_def.get("type") or "").strip()

    if rtype == "content_regex":
        pattern = rule_def.get("pattern")
        if not isinstance(pattern, str) or not pattern:
            return False
        flags = rule_def.get("flags")
        if flags is not None and not isinstance(flags, list):
            flags = None
        nodes = report.get("nodes", []) or []
        text = "\n".join((n.get("content_preview") or "") for n in nodes)
        # Bounded evaluation: pack patterns are attacker-influenced and re has
        # no timeout, so a catastrophic-backtracking pattern is capped by a hard
        # wall-clock limit (or run under linear-time RE2 if installed).
        return content_regex_search(pattern, flags, text)

    if rtype == "ioc_present":
        ioc_types = rule_def.get("ioc_types")
        if not isinstance(ioc_types, list) or not ioc_types:
            return False
        min_each = int(rule_def.get("min_each", 1))
        for t in ioc_types:
            values = iocs.get(str(t), []) or []
            if len(values) < min_each:
                return False
        return True

    # Unknown type
    return False
