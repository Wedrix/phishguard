# Controlled change record

Record requirement, architecture, security, privacy, data/model, and operational baseline changes here. Entries are append-only: correct an entry with a dated follow-up rather than silently rewriting its outcome. A change is not accepted merely because code exists; repository verification and live acceptance evidence remain separate.

## CR-2026-07-23-02: Installable client, evidence usability and governed workspace completion

- Status: Implemented candidate; live acceptance pending
- Drivers: device-consistent presentation, installability, clearer evidence interpretation, public privacy/process transparency, and closure of prototype-to-implementation workflow gaps.
- Baseline impact: the public shell now follows the device light/dark preference and exposes dedicated How it works and Privacy routes. An install manifest and application icons are provided without an offline scan cache. Evidence values remain typed through the API and are rendered as bounded responsive cards with neutral state language and provenance details.
- Functional impact: adds recent scans, history search/filter, controlled re-scan and decision export, optional research consent, analyst queue/citation/reveal workflows, real administration telemetry and deployment gates, audit-chain verification, and queued dataset experiment/export processing.
- Security/privacy impact: no submitted URL is opened by the client. Analyst URL reveal requires a claimed case and fresh authentication and is audited. Research export requires explicit consent plus independent adjudication and excludes comments, identity fields and decrypted URLs. Installability does not introduce background retrieval or sensitive offline caching.
- Data/model impact: adds one feedback consent field and governed evaluator/export state transitions. Model registry approval now requires explicit data, feature, evaluation and security gates and remains separate from digest-pinned runtime deployment.
- Rollout: apply Alembic revision `0005`, deploy backend before the compatible client, verify the evaluation CronJob mount and rendered placeholders, then exercise device themes, installation, public routes, responsive evidence, all role journeys and one queued research job.
- Rollback: retain the additive consent column and registry records, redeploy the prior compatible application digest, and leave queued/running research records for explicit operator review. Do not delete audit or adjudication history.
- Repository evidence: 103 backend tests, 40 frontend tests, 41 isolated-fetcher tests, TypeScript compilation, production Vite build, a complete Alembic `0001`–`0005` migration exercise and rendered Kustomize manifests. Live browser/device installation, GKE, Web Risk, accessibility and user-comprehension evidence remains pending.

## CR-2026-07-23-01: Privileged-role governance and administrator continuity

- Status: Implemented candidate; live acceptance pending
- Decision: ADR-0007
- Drivers: prevent requested-role self-escalation; permit bounded delegation; preserve one operator-controlled root of authority; make administrator succession explicit and auditable.
- Baseline impact: replaces the earlier v1 restriction against in-application Administrator appointment. Registration choices remain non-authoritative. Any active Administrator may appoint a qualified non-canonical Administrator, while only the canonical Administrator may demote or disable a current delegated Administrator. Canonical bootstrap and transfer remain operator-only.
- Affected requirements: identity assurance, application RBAC, registration, administration, session revocation, recent authentication, idempotency, audit integrity, privacy transparency, deployment, recovery, and traceability.
- Security impact: reduces accidental canonical lockout and adds target assurance and session revocation. It increases the authority available to a compromised delegated Administrator because one Administrator can appoint another without a second approver; ADR-0007 and the threat/debt records retain this residual risk.
- Privacy impact: stores requested role, request state, account/object identifiers, lifecycle timestamps, an optional bounded decision note, and chained governance events. Decision notes are intended only for governance rationale and must not contain submitted URLs, provider evidence, secrets, tokens, or unnecessary personal information. These records are outside scan-data deletion.
- Data/model impact: none. Role requests and appointments cannot enter a training snapshot or alter an existing decision.
- Related debt: DEBT-016 (single-approver privilege governance and no independent break-glass path) and DEBT-017 (governance-record retention, export and free-text controls).
- Rollout: apply the additive schema migration, deploy the compatible application by digest, designate the canonical account when required, and exercise request, approval, appointment, session-revocation, and denial paths. Follow the deployment runbook.
- Rollback: retain the forward-only schema and audit history. Redeploy the preceding compatible image digests; do not delete request or audit rows. A planned rollback must first review pending requests and delegated Administrators because the preceding application cannot administer the new workflow. Follow the deployment runbook.
- Repository evidence: database constraints and migration, account/governance API tests, operator-command tests, and role-aware interface tests. Exact live Identity Platform and GKE behavior remains unverified until the dated exercises below are archived.
- Acceptance still required: real-tenant TOTP and role matrix; canonical bootstrap and transfer rehearsal; concurrent approval/idempotency exercise; audit-chain inspection; rollback rehearsal; manual accessibility review of request and administration journeys.
