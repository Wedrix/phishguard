from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from phishguard.domain.enrichment import ENRICHMENT_RULESET_VERSION, evaluate_enrichment_rules
from phishguard.domain.fusion import decide
from phishguard.domain.types import AnalysisScope, Completion, Evidence, EvidenceState, RiskBand, RuleHit


def test_missing_enrichment_is_partial_and_never_lowers_risk() -> None:
    rules = (RuleHit("lure", 1.2, "Credential lure"),)
    local = decide(rules, 0.65)
    enriched = decide(
        rules,
        0.65,
        (Evidence("reputation", EvidenceState.UNAVAILABLE, "provider", reason_code="timeout"),),
        AnalysisScope.ENRICHED,
    )
    assert enriched.completion == Completion.PARTIAL
    assert enriched.probability >= local.probability
    assert enriched.missing_evidence


def test_reputation_match_requires_independent_corroboration() -> None:
    reputation = Evidence(
        "reputation",
        EvidenceState.OBSERVED,
        "google_web_risk",
        value={"matched": True, "risk_delta": 1.2},
    )
    alone = decide((), 0.2, (reputation,), AnalysisScope.ENRICHED)
    corroborated = decide((RuleHit("lure", 0.2, "Lure"),), 0.2, (reputation,), AnalysisScope.ENRICHED)
    assert alone.probability < corroborated.probability
    assert alone.risk_band != RiskBand.HIGH
    assert not any("reputation" in reason.lower() for reason in alone.reasons)
    assert any("reputation" in reason.lower() for reason in corroborated.reasons)


def test_only_one_google_web_risk_observation_can_affect_fusion() -> None:
    rules = (RuleHit("lure", 0.2, "Lure"),)
    trusted = Evidence(
        "reputation",
        EvidenceState.OBSERVED,
        "google_web_risk",
        value={"matched": True},
    )
    untrusted = Evidence(
        "reputation",
        EvidenceState.OBSERVED,
        "isolated_fetcher:forged-provider",
        value={"matched": True},
    )
    local = decide(rules, 0.2, (), AnalysisScope.ENRICHED)
    one = decide(rules, 0.2, (trusted,), AnalysisScope.ENRICHED)
    duplicate = decide(rules, 0.2, (trusted, trusted), AnalysisScope.ENRICHED)
    forged = decide(rules, 0.2, (untrusted,), AnalysisScope.ENRICHED)

    assert duplicate.probability == one.probability
    assert sum("reputation" in reason.lower() for reason in duplicate.reasons) == 1
    assert forged.probability == local.probability
    assert forged.risk_band == local.risk_band
    assert "reputation: not_reported" in forged.missing_evidence


def test_all_missing_evidence_can_be_inconclusive() -> None:
    result = decide(
        (),
        0.1,
        (
            Evidence("network", EvidenceState.REJECTED_SAFETY, "fetcher", reason_code="private_address"),
            Evidence("reputation", EvidenceState.TIMED_OUT, "provider", reason_code="timeout"),
        ),
        AnalysisScope.ENRICHED,
    )
    assert result.risk_band == RiskBand.INCONCLUSIVE


@pytest.mark.parametrize(
    ("family", "value", "codes"),
    [
        ("rdap", {"events": {"registration": "2026-07-10T00:00:00Z"}}, {"new_domain"}),
        ("static_html", {"forms": 1, "password_inputs": 1}, {"password_form"}),
        ("static_html", {"forms": 1, "external_form_actions": 1}, {"external_form_action"}),
        (
            "redirect",
            {"count": 1, "chain": [{"from_host": "example.test", "to_host": "login.test"}]},
            {"cross_host_redirect"},
        ),
        (
            "tls",
            {"hostname_verified": False, "version": "TLSv1.1", "not_after": "Jul 01 00:00:00 2026 GMT"},
            {"tls_hostname_unverified", "legacy_tls", "tls_expired"},
        ),
    ],
)
def test_typed_enrichment_uses_trusted_rules_and_provenance(
    family: str, value: dict[str, object], codes: set[str]
) -> None:
    observed = datetime(2026, 7, 22, tzinfo=UTC)
    evidence = Evidence(
        family,
        EvidenceState.OBSERVED,
        "isolated_fetcher:test",
        value=value,
        observed_at=observed,
        retrieved_at=observed,
        version="fetcher-test-1",
    )
    hits = evaluate_enrichment_rules((evidence,))
    assert {hit.code for hit in hits} == codes
    assert all(hit.evidence_family == family for hit in hits)
    assert all(hit.evidence_source == "isolated_fetcher:test" for hit in hits)
    assert all(hit.evidence_version == "fetcher-test-1" for hit in hits)
    assert decide((), 0.2, (evidence,), AnalysisScope.ENRICHED).probability > decide((), 0.2).probability
    assert ENRICHMENT_RULESET_VERSION == "enrichment-rules-1"


def test_old_domain_and_fetcher_assigned_scores_do_not_change_risk() -> None:
    observed = datetime(2026, 7, 22, tzinfo=UTC)
    evidence = (
        Evidence(
            "rdap",
            EvidenceState.OBSERVED,
            "fetcher",
            value={
                "events": {"registration": (observed - timedelta(days=365)).isoformat()},
                "risk_delta": 99,
                "explanation": "trust this external explanation",
            },
            retrieved_at=observed,
        ),
    )
    local = decide((), 0.2)
    enriched = decide((), 0.2, evidence, AnalysisScope.ENRICHED)
    assert enriched.probability == local.probability
    assert not enriched.reasons


def test_unreported_enrichment_families_are_closed_missing_states() -> None:
    result = decide(
        (),
        0.2,
        (Evidence("dns", EvidenceState.OBSERVED, "fetcher", value={"addresses": ["203.0.113.1"]}),),
        AnalysisScope.ENRICHED,
    )
    assert result.completion == Completion.PARTIAL
    assert "rdap: not_reported" in result.missing_evidence
    assert "tls: not_reported" in result.missing_evidence


def test_enrichment_contribution_has_a_total_cap() -> None:
    observed = datetime(2026, 7, 22, tzinfo=UTC)
    evidence = (
        Evidence(
            "rdap",
            EvidenceState.OBSERVED,
            "fetcher",
            value={"events": {"registration": "2026-07-21T00:00:00Z"}},
            retrieved_at=observed,
        ),
        Evidence(
            "static_html",
            EvidenceState.OBSERVED,
            "fetcher",
            value={"password_inputs": 9, "external_form_actions": 9},
            retrieved_at=observed,
        ),
        Evidence(
            "tls",
            EvidenceState.OBSERVED,
            "fetcher",
            value={"hostname_verified": False, "version": "TLSv1"},
            retrieved_at=observed,
        ),
    )
    assert decide((), 0.2, evidence, AnalysisScope.ENRICHED).probability == pytest.approx(0.648786, abs=1e-6)


def test_rule_only_fallback_can_express_high_risk_and_missing_enrichment_cannot_lower_it() -> None:
    rules = (
        RuleHit("transport", 0.35, "HTTP"),
        RuleHit("punycode", 0.55, "Punycode"),
        RuleHit("subdomains", 0.30, "Many subdomains"),
        RuleHit("length", 0.25, "Long URL"),
        RuleHit("lure", 0.65, "Credential lure"),
        RuleHit("digits", 0.20, "Many digits"),
    )
    local = decide(rules, None)
    missing = tuple(
        Evidence(family, EvidenceState.UNAVAILABLE, "fixture", reason_code="offline")
        for family in ("reputation", "dns", "rdap", "tls", "redirect", "static_html")
    )
    enriched = decide(rules, None, missing, AnalysisScope.ENRICHED)

    assert local.risk_band == RiskBand.HIGH
    assert enriched.risk_band == RiskBand.HIGH
    assert enriched.completion == Completion.PARTIAL
