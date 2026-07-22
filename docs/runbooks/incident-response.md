# Incident-response runbook

## Triage and containment

1. Declare severity, incident commander, start time, affected commit/images/model/policy, and a URL-free correlation window.
2. For suspected unsafe retrieval or fetcher compromise, set `ENRICHMENT_ENABLED=false`, scale `jobs` and `fetcher` to zero, and preserve pod/runtime/audit evidence. Local-only analysis may remain available only if unaffected.
3. For credential compromise, disable affected Secret Manager versions or Identity Platform accounts, revoke application sessions, rotate the provider key or full mTLS set, and redeploy. Never paste a URL or secret into chat, tickets, or logs.
4. For integrity concerns, stop model/policy activation and exports; preserve database/PITR time, artefact generations, audit-chain head, image digests, and Cloud Build provenance.
5. For provider outage, leave local analysis available. Confirm scans show `UNAVAILABLE`/`PARTIAL`; do not bypass consent or reinterpret no evidence as safe.

## Recovery and closure

Patch the root cause, run the smallest regression plus security suite, deploy by digest, verify audit-chain continuity and a local-only no-egress scan, then restore enrichment. Notify affected users according to institutional policy. Close with timeline, impact, data/provider exposure, corrective actions, RTM/threat/debt updates, owners, and due dates.

