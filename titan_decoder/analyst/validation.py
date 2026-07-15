"""Answer validation: citations must resolve, factual bullets must cite.

Model output is untrusted. An answer is accepted only when every citation
resolves to a real ledger entry and every factual bullet (dash, asterisk,
or numbered) carries at least one citation. Anything else falls back to
the deterministic answer.
"""

from __future__ import annotations

from dataclasses import dataclass
import re

from .evidence import EvidenceIndex

_CITATION = re.compile(r"\[([a-z_]+:[^\]\s]+)\]")
_BULLET = re.compile(r"^(-|\*|\d+[.)])\s")
_NON_CLAIM_PREFIXES = ("Titan did not", "I cannot", "No evidence", "Inference:")


@dataclass(frozen=True)
class AnswerValidation:
    ok: bool
    citations: tuple[str, ...]
    invalid: tuple[str, ...]
    uncited_claim_lines: tuple[int, ...]


def validate_answer(text: str, index: EvidenceIndex) -> AnswerValidation:
    citations = tuple(dict.fromkeys(_CITATION.findall(text)))
    invalid = tuple(c for c in citations if c not in index.by_id)
    uncited: list[int] = []
    for number, line in enumerate(text.splitlines(), 1):
        clean = line.strip()
        if not clean or clean.endswith(":") or clean.startswith(_NON_CLAIM_PREFIXES):
            continue
        if _BULLET.match(clean) and not _CITATION.search(clean):
            uncited.append(number)
    return AnswerValidation(
        ok=not invalid and not uncited,
        citations=citations,
        invalid=invalid,
        uncited_claim_lines=tuple(uncited),
    )
