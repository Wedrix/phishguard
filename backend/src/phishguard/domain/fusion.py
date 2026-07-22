from __future__ import annotations

import math

from phishguard.domain.enrichment import (
    EXPECTED_ENRICHMENT_FAMILIES,
    MAX_ENRICHMENT_LOG_ODDS,
    evaluate_enrichment_rules,
)
from phishguard.domain.types import (
    AnalysisScope,
    Completion,
    DecisionResult,
    EngineMode,
    Evidence,
    EvidenceState,
    RiskBand,
    RuleHit,
)

FUSION_VERSION = "log-odds-3"
REPUTATION_LOG_ODDS = 1.0
HYBRID_HIGH_THRESHOLD = 0.72
HYBRID_MEDIUM_THRESHOLD = 0.38
# A rule-only score is a bounded prioritisation signal, not a calibrated model
# probability. Separate declared thresholds keep the fallback capable of
# expressing HIGH risk when several deterministic indicators agree.
RULE_ONLY_HIGH_THRESHOLD = 0.55
RULE_ONLY_MEDIUM_THRESHOLD = 0.20
_MISSING = {
    EvidenceState.SKIPPED_POLICY,
    EvidenceState.UNAVAILABLE,
    EvidenceState.TIMED_OUT,
    EvidenceState.REJECTED_SAFETY,
    EvidenceState.STALE,
}


def _logit(probability: float) -> float:
    bounded = min(0.999, max(0.001, probability))
    return math.log(bounded / (1 - bounded))


def _sigmoid(value: float) -> float:
    return 1 / (1 + math.exp(-value))


def decide(
    rules: tuple[RuleHit, ...],
    model_probability: float | None,
    evidence: tuple[Evidence, ...] = (),
    scope: AnalysisScope = AnalysisScope.LOCAL_ONLY,
    enrichment_rules: tuple[RuleHit, ...] | None = None,
) -> DecisionResult:
    engine_mode = EngineMode.HYBRID if model_probability is not None else EngineMode.RULE_ONLY
    baseline = model_probability if model_probability is not None else 0.12
    trusted_enrichment = evaluate_enrichment_rules(evidence) if enrichment_rules is None else enrichment_rules
    odds = _logit(baseline) + sum(hit.weight for hit in rules)
    odds += min(MAX_ENRICHMENT_LOG_ODDS, sum(hit.weight for hit in trusted_enrichment))
    corroborated = bool(rules) or (model_probability is not None and model_probability >= 0.55)
    reasons = [hit.message for hit in sorted((*rules, *trusted_enrichment), key=lambda item: item.weight, reverse=True)]
    counter: list[str] = []
    missing: list[str] = []
    accepted_families: set[str] = set()
    accepted_evidence: list[Evidence] = []
    reputation_seen = False

    for item in evidence:
        if item.family == "reputation":
            if item.source != "google_web_risk" or reputation_seen:
                continue
            reputation_seen = True
        accepted_families.add(item.family)
        accepted_evidence.append(item)
        if item.state in _MISSING:
            missing.append(f"{item.family}: {item.reason_code or item.state.value.lower()}")
            continue
        if item.state == EvidenceState.NO_MATCH:
            if item.family == "reputation":
                counter.append("The configured reputation source had no matching threat entry.")
            continue
        if item.state != EvidenceState.OBSERVED:
            continue
        if item.family == "reputation" and item.value.get("matched") is True:
            if corroborated:
                odds += REPUTATION_LOG_ODDS
                reasons.append("The URL matched the configured phishing reputation source.")

    if scope == AnalysisScope.ENRICHED:
        missing.extend(
            f"{family}: not_reported" for family in sorted(EXPECTED_ENRICHMENT_FAMILIES - accepted_families)
        )

    probability = _sigmoid(odds)
    completion = Completion.PARTIAL if missing else Completion.COMPLETE
    usable = any(
        item.family in EXPECTED_ENRICHMENT_FAMILIES
        and item.state in {EvidenceState.OBSERVED, EvidenceState.NO_MATCH, EvidenceState.NOT_APPLICABLE}
        for item in accepted_evidence
    )
    high_threshold = (
        HYBRID_HIGH_THRESHOLD if engine_mode == EngineMode.HYBRID else RULE_ONLY_HIGH_THRESHOLD
    )
    medium_threshold = (
        HYBRID_MEDIUM_THRESHOLD if engine_mode == EngineMode.HYBRID else RULE_ONLY_MEDIUM_THRESHOLD
    )
    risk_band = (
        RiskBand.HIGH
        if probability >= high_threshold
        else RiskBand.MEDIUM
        if probability >= medium_threshold
        else RiskBand.LOW
    )
    if scope == AnalysisScope.ENRICHED and not usable and risk_band != RiskBand.HIGH:
        risk_band = RiskBand.INCONCLUSIVE

    limitations = ["Automated analysis cannot guarantee that a URL is safe."]
    if engine_mode == EngineMode.RULE_ONLY:
        limitations.append("The approved machine-learning model was unavailable; deterministic rules were used.")
    if missing:
        limitations.append("Some enrichment evidence was missing and was not treated as benign.")
    return DecisionResult(
        risk_band=risk_band,
        analysis_scope=scope,
        completion=completion,
        engine_mode=engine_mode,
        probability=round(probability, 6),
        reasons=tuple(dict.fromkeys(reasons))[:3],
        counter_evidence=tuple(dict.fromkeys(counter))[:3],
        missing_evidence=tuple(missing),
        limitations=tuple(limitations),
    )
