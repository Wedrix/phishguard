# ADR-0004: Local-first, consented reputation

- Status: Accepted
- Date: 2026-07-22

## Context

Google Web Risk Lookup receives the full submitted URL. Disclosure is unnecessary for local structural analysis and may expose sensitive path or query data.

## Decision

Default to `LOCAL_ONLY`. Run Web Risk and all other URL-derived network activity only after an affirmative enrichment choice tied to a persisted notice version. Use Web Risk as evidence, never training labels or sole classification authority.

## Consequences

Users retain a meaningful privacy-preserving mode. Provider failure creates `UNAVAILABLE` or `PARTIAL`, not a safe result or HTTP server error.

