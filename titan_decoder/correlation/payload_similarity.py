"""Shared payload detection across analyses.

Builds a deterministic fingerprint per report from node content hashes and
the decode chain, then scores pairwise similarity. An exact content-hash
match dominates the score; fuzzy/import/resource hashes (when a report
carries them) and decode-chain overlap corroborate.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from .models import stable_id

SCHEMA_VERSION = "shared-payload-v1.0"


@dataclass(frozen=True)
class PayloadFingerprint:
    """Hash-level summary of the payloads inside one analysis."""

    analysis_id: str
    root_hash: str
    payload_hashes: tuple[str, ...] = ()
    fuzzy_hashes: tuple[str, ...] = ()
    import_hashes: tuple[str, ...] = ()
    resource_hashes: tuple[str, ...] = ()
    decode_chain: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "analysis_id": self.analysis_id,
            "root_hash": self.root_hash,
            "payload_hashes": list(self.payload_hashes),
            "fuzzy_hashes": list(self.fuzzy_hashes),
            "import_hashes": list(self.import_hashes),
            "resource_hashes": list(self.resource_hashes),
            "decode_chain": list(self.decode_chain),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "PayloadFingerprint":
        return cls(
            analysis_id=str(data["analysis_id"]),
            root_hash=str(data.get("root_hash") or ""),
            payload_hashes=tuple(data.get("payload_hashes") or ()),
            fuzzy_hashes=tuple(data.get("fuzzy_hashes") or ()),
            import_hashes=tuple(data.get("import_hashes") or ()),
            resource_hashes=tuple(data.get("resource_hashes") or ()),
            decode_chain=tuple(data.get("decode_chain") or ()),
        )


@dataclass(frozen=True)
class SharedPayload:
    """One payload-similarity match between two analyses."""

    left_analysis_id: str
    right_analysis_id: str
    score: float
    reasons: tuple[str, ...]

    @property
    def match_id(self) -> str:
        return stable_id(
            "shared-payload",
            {
                "left": self.left_analysis_id,
                "right": self.right_analysis_id,
                "reasons": list(self.reasons),
            },
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "match_id": self.match_id,
            "left_analysis_id": self.left_analysis_id,
            "right_analysis_id": self.right_analysis_id,
            "score": round(self.score, 6),
            "reasons": list(self.reasons),
        }


def _jaccard(left: Iterable[str], right: Iterable[str]) -> float:
    left_set, right_set = set(left), set(right)
    union = left_set | right_set
    if not union:
        return 0.0
    return len(left_set & right_set) / len(union)


def fingerprint_from_report(report: Mapping[str, Any]) -> PayloadFingerprint:
    """Build a payload fingerprint from an analysis report."""

    meta = report.get("meta") or {}
    analysis_id = str(
        meta.get("analysis_id")
        or report.get("analysis_id")
        or report.get("root_hash")
        or ""
    )
    root_hash = str(report.get("root_hash") or meta.get("root_hash") or "")

    hashes: set[str] = set()
    fuzzy: set[str] = set()
    imports: set[str] = set()
    resources: set[str] = set()
    chain: list[str] = []
    for node in report.get("nodes") or ():
        if not isinstance(node, Mapping):
            continue
        for key in ("sha256", "content_hash", "payload_hash", "hash"):
            if node.get(key):
                hashes.add(str(node[key]))
        if node.get("parent") is None and node.get("sha256") and not root_hash:
            root_hash = str(node["sha256"])
        if node.get("ssdeep"):
            fuzzy.add("ssdeep:" + str(node["ssdeep"]))
        if node.get("tlsh"):
            fuzzy.add("tlsh:" + str(node["tlsh"]))
        if node.get("imphash"):
            imports.add(str(node["imphash"]))
        for value in node.get("resource_hashes") or ():
            resources.add(str(value))
        operation = node.get("decoder_used") or node.get("method")
        if operation:
            chain.append(str(operation))
    if root_hash:
        hashes.add(root_hash)

    return PayloadFingerprint(
        analysis_id=analysis_id,
        root_hash=root_hash,
        payload_hashes=tuple(sorted(hashes)),
        fuzzy_hashes=tuple(sorted(fuzzy)),
        import_hashes=tuple(sorted(imports)),
        resource_hashes=tuple(sorted(resources)),
        decode_chain=tuple(chain),
    )


def detect_shared_payloads(
    fingerprints: Iterable[PayloadFingerprint],
    *,
    minimum_score: float = 0.35,
) -> dict[str, Any]:
    """Score every fingerprint pair and keep matches at or above the floor."""

    if not 0.0 <= minimum_score <= 1.0:
        raise ValueError("minimum_score must be between 0 and 1")

    items = sorted(fingerprints, key=lambda item: item.analysis_id)
    matches: list[SharedPayload] = []
    for index, left in enumerate(items):
        for right in items[index + 1 :]:
            if left.analysis_id == right.analysis_id:
                continue
            exact = bool(set(left.payload_hashes) & set(right.payload_hashes))
            fuzzy = _jaccard(left.fuzzy_hashes, right.fuzzy_hashes)
            imports = _jaccard(left.import_hashes, right.import_hashes)
            resources = _jaccard(left.resource_hashes, right.resource_hashes)
            chain = _jaccard(left.decode_chain, right.decode_chain)
            score = min(
                1.0,
                (0.55 if exact else 0.0)
                + 0.15 * fuzzy
                + 0.15 * imports
                + 0.10 * resources
                + 0.05 * chain,
            )
            reasons: list[str] = []
            if exact:
                reasons.append("exact_payload_hash")
            if fuzzy:
                reasons.append("shared_fuzzy_hash")
            if imports:
                reasons.append("shared_import_hash")
            if resources:
                reasons.append("shared_resource_hash")
            if chain:
                reasons.append("decode_chain_similarity")
            if score >= minimum_score and reasons:
                matches.append(
                    SharedPayload(
                        left.analysis_id, right.analysis_id, score, tuple(reasons)
                    )
                )

    matches.sort(key=lambda match: (-match.score, match.match_id))
    return {
        "schema_version": SCHEMA_VERSION,
        "match_count": len(matches),
        "matches": [match.to_dict() for match in matches],
    }
