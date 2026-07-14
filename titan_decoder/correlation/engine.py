"""Correlation orchestration for one subject analysis."""

from __future__ import annotations

from .database import CorrelationDatabase
from .models import AnalysisRecord, CorrelationReport
from .relationships import RelationshipScorer


class CorrelationEngine:
    """Compare one analysis with persisted prior analyses."""

    def __init__(
        self,
        database: CorrelationDatabase,
        scorer: RelationshipScorer | None = None,
        minimum_score: float = 0.0,
    ):
        if not 0.0 <= minimum_score <= 1.0:
            raise ValueError("minimum_score must be between 0 and 1")
        self.database = database
        self.scorer = scorer or RelationshipScorer()
        self.minimum_score = minimum_score

    def correlate(
        self,
        subject: AnalysisRecord,
        *,
        record_subject: bool = True,
    ) -> CorrelationReport:
        relationships = []
        for candidate in self.database.iter_analyses(
            exclude_analysis_id=subject.analysis_id
        ):
            relationship = self.scorer.score(subject, candidate)
            if relationship.score >= self.minimum_score and relationship.score > 0.0:
                relationships.append(relationship)

        report = CorrelationReport(
            subject_analysis_id=subject.analysis_id,
            relationships=tuple(relationships),
        )
        if record_subject:
            self.database.record_analysis(subject)
        return report
