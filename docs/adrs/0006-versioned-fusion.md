# ADR-0006: Versioned evidence fusion

- Status: Accepted
- Date: 2026-07-22

## Context

Rules, model output, reputation, and retrieved evidence have different provenance and failure modes. Treating missing evidence as false would produce unsafe confidence.

## Decision

Fuse calibrated URL-model log odds, bounded deterministic rule contributions, and corroborated independent evidence under a versioned policy. Hybrid and rule-only modes use separately declared thresholds because the fallback score is a prioritisation signal rather than a calibrated probability; the fallback must still be able to express `HIGH` when several deterministic indicators agree. Store immutable local and final decisions with ruleset, model, calibration, policy, and observation references. Preserve closed evidence states.

## Consequences

Decisions are reproducible and explainable. Model failure visibly falls back to rules. Missing enrichment can reduce completeness or yield `INCONCLUSIVE`, but cannot reduce risk.
