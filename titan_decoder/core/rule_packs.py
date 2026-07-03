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

Supported rule types:
- content_regex: regex over concatenated node content_preview
- ioc_present: requires one or more IOC types to meet minimum counts

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

    return RulePackInfo(
        name=name, version=version, schema_version=schema_version, path=str(path)
    ), rules


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


def compile_content_regex(pattern: str, flags: Optional[List[str]] = None) -> re.Pattern:
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
