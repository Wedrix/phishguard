from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


class EvidenceState(StrEnum):
    OBSERVED = "OBSERVED"
    NO_MATCH = "NO_MATCH"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    SKIPPED_POLICY = "SKIPPED_POLICY"
    UNAVAILABLE = "UNAVAILABLE"
    TIMED_OUT = "TIMED_OUT"
    REJECTED_SAFETY = "REJECTED_SAFETY"
    STALE = "STALE"


class RiskBand(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    INCONCLUSIVE = "INCONCLUSIVE"


class AnalysisScope(StrEnum):
    LOCAL_ONLY = "LOCAL_ONLY"
    ENRICHED = "ENRICHED"


class Completion(StrEnum):
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"


class EngineMode(StrEnum):
    HYBRID = "HYBRID"
    RULE_ONLY = "RULE_ONLY"


class Role(StrEnum):
    REGISTERED_USER = "REGISTERED_USER"
    ANALYST = "ANALYST"
    ADMINISTRATOR = "ADMINISTRATOR"
    RESEARCHER = "RESEARCHER"


@dataclass(frozen=True, slots=True)
class RuleHit:
    code: str
    weight: float
    message: str
    evidence_family: str | None = None
    evidence_source: str | None = None
    evidence_version: str | None = None


@dataclass(frozen=True, slots=True)
class Evidence:
    family: str
    state: EvidenceState
    source: str
    value: dict[str, Any] = field(default_factory=dict)
    observed_at: datetime | None = None
    retrieved_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime | None = None
    version: str = "1"
    cached: bool = False
    sensitivity: str = "INTERNAL"
    reason_code: str | None = None


@dataclass(frozen=True, slots=True)
class DecisionResult:
    risk_band: RiskBand
    analysis_scope: AnalysisScope
    completion: Completion
    engine_mode: EngineMode
    probability: float
    reasons: tuple[str, ...]
    counter_evidence: tuple[str, ...]
    missing_evidence: tuple[str, ...]
    limitations: tuple[str, ...]
    safe_actions: tuple[str, ...] = (
        "Do not enter credentials or payment details on a suspicious page.",
        "Verify the destination through an independent trusted channel.",
    )
