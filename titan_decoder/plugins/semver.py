"""Semantic versioning for the plugin SDK.

Implements SemVer 2.0.0 parsing, precedence (including correct pre-release
ordering: ``1.0.0-alpha < 1.0.0``), API compatibility for manifests, and the
requirement syntax used by plugin dependency constraints (``^``, ``~``,
comparator lists, exact versions, and ``*``).
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import total_ordering
import re
from typing import Any

_SEMVER_RE = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)


def _prerelease_key(prerelease: str) -> tuple[Any, ...]:
    """Precedence key for a pre-release string per SemVer 2.0.0.

    A release (empty pre-release) sorts after every pre-release. Numeric
    identifiers compare numerically and rank below alphanumeric ones.
    """

    if not prerelease:
        return (1,)
    parts: list[tuple[int, Any]] = []
    for identifier in prerelease.split("."):
        if identifier.isdigit():
            parts.append((0, int(identifier)))
        else:
            parts.append((1, identifier))
    return (0, tuple(parts))


@total_ordering
@dataclass(frozen=True)
class Version:
    """Parsed semantic version with correct precedence ordering."""

    major: int
    minor: int
    patch: int
    prerelease: str = ""

    @classmethod
    def parse(cls, value: "str | Version") -> "Version":
        if isinstance(value, Version):
            return value
        text = str(value).strip()
        # Accept MAJOR.MINOR shorthand (the legacy PLUGIN_API_VERSION form).
        if re.fullmatch(r"\d+\.\d+", text):
            text += ".0"
        match = _SEMVER_RE.fullmatch(text)
        if not match:
            raise ValueError(f"invalid semantic version: {value!r}")
        return cls(
            int(match.group(1)),
            int(match.group(2)),
            int(match.group(3)),
            match.group(4) or "",
        )

    def _key(self) -> tuple[Any, ...]:
        return (self.major, self.minor, self.patch, _prerelease_key(self.prerelease))

    def __lt__(self, other: "Version") -> bool:
        if not isinstance(other, Version):
            return NotImplemented
        return self._key() < other._key()

    def __str__(self) -> str:
        base = f"{self.major}.{self.minor}.{self.patch}"
        return f"{base}-{self.prerelease}" if self.prerelease else base


def is_manifest_api_compatible(declared: str, provided: str) -> bool:
    """API compatibility rule for manifest plugins.

    A plugin is loadable when its declared API has the same MAJOR as the
    engine's and requires no MINOR features newer than the engine provides.
    Raises ``ValueError`` for malformed versions (manifest validation
    surfaces that as a manifest error).
    """

    declared_version = Version.parse(declared)
    provided_version = Version.parse(provided)
    return (
        declared_version.major == provided_version.major
        and declared_version.minor <= provided_version.minor
    )


def satisfies(version: "str | Version", requirement: str) -> bool:
    """Return True if *version* satisfies a dependency *requirement*.

    Supported forms: ``*`` / empty (anything), ``^X.Y.Z`` (compatible within
    the major), ``~X.Y.Z`` (compatible within the minor), comma-separated
    comparators (``>=1.0.0,<2.0.0``), and an exact version.
    """

    value = Version.parse(version)
    text = requirement.strip()
    if text in {"", "*"}:
        return True
    if text.startswith("^"):
        floor = Version.parse(text[1:])
        return floor <= value < Version(floor.major + 1, 0, 0)
    if text.startswith("~"):
        floor = Version.parse(text[1:])
        return floor <= value < Version(floor.major, floor.minor + 1, 0)
    if "," in text or text.startswith((">", "<", "=")):
        for clause in text.split(","):
            clause = clause.strip()
            operator = next(
                (op for op in (">=", "<=", "==", ">", "<") if clause.startswith(op)),
                None,
            )
            if operator is None:
                raise ValueError(f"invalid version requirement clause: {clause!r}")
            target = Version.parse(clause[len(operator) :].strip())
            satisfied = {
                ">=": value >= target,
                "<=": value <= target,
                "==": value == target,
                ">": value > target,
                "<": value < target,
            }[operator]
            if not satisfied:
                return False
        return True
    return value == Version.parse(text)
