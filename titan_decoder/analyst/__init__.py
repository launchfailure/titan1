"""Local AI Analyst: grounded, citation-enforced explanation of Titan reports."""

from .backend import AnalystBackend, BackendResult, LocalOpenAIBackend, ScriptedBackend
from .engine import AnalystEngine, AnalystResponse
from .evidence import EvidenceIndex, EvidenceItem
from .questions import QuestionPlan, plan_question
from .validation import AnswerValidation, validate_answer

__all__ = [
    "AnalystBackend",
    "AnalystEngine",
    "AnalystResponse",
    "AnswerValidation",
    "BackendResult",
    "EvidenceIndex",
    "EvidenceItem",
    "LocalOpenAIBackend",
    "QuestionPlan",
    "ScriptedBackend",
    "plan_question",
    "validate_answer",
]
