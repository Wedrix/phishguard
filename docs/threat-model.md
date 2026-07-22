# Threat model

## Scope, assets, and trust boundaries

Protected assets are submitted URLs, identity/session data, roles, decisions and evidence, model/dataset artefacts, provider credentials, encryption keys, audit integrity, and platform availability.

Trust boundaries are: browser to Gateway/web; web/jobs to PostgreSQL and Google APIs; jobs to the fetcher over mTLS; fetcher to attacker-controlled Internet hosts; and researcher/admin workflows to governed artefacts. The fetcher is untrusted relative to application data even though its image is maintained by the project.

## Principal threats and controls

| Threat | Primary controls | Verification |
|---|---|---|
| SSRF, redirects, rebinding, encoded IP bypass | Strict URL grammar; DNS-set validation; connection pinning with hostname SNI/certificate checks; repeat on redirects; public 80/443 only; NetworkPolicy | Direct/redirect/rebinding fetcher tests |
| Malicious or oversized content | No JavaScript/subresources/cookies; MIME allowlist; header/body/decompression/time budgets; raw body never crosses boundary | Compression, slow, MIME, malformed HTML tests |
| URL disclosure without consent | Local-only orchestration gate before every URL-derived lookup; persisted notice version; no external cache use in local mode | E2E network-spy test |
| Sensitive logging | Structured allowlisted fields; URL-free correlation IDs and metrics; no bodies, query strings, email, or tokens | Log-capture tests and release review |
| Account or privilege takeover | Identity Platform verified email/TOTP; opaque session; CSRF; secure cookies; recent auth; server-side RBAC/object checks | Role matrix, revocation, CSRF, reauth tests |
| Model/provider over-reliance | Versioned rules/model/policy; corroboration; neutral `NO_MATCH`; explicit missing states; rule-only fallback | Fusion, outage, and ablation tests |
| Feedback/data poisoning | Quarantine, independent adjudication, immutable snapshots and manifests; no automatic retraining | Governance workflow tests |
| Secret or workload compromise | KMS/Secret Manager; least-privilege Workload Identity; credentialless gVisor fetcher; read-only roots; digest images | IAM review, pod-spec checks, secret rotation drill |
| Queue replay or duplicate effects | Transactional creation, leases, bounded retry, idempotency keys and evidence constraints | Crash/reclaim and duplicate-request tests |
| Audit tampering | Append-only events, previous-event HMAC, daily URL-free Cloud Logging anchor | Chain verification and mutation test |
| Resource exhaustion/abuse | URL/body/time limits, PostgreSQL counters, Cloud Armor throttle, bounded job concurrency | k6 and quota/failure tests |
| Supply-chain compromise | Locked dependencies, CI tests, separate minimal images, digest deployment, Artifact Registry | Build provenance/dependency review |

## Residual risks

This single-region demo is not highly available. NetworkPolicy is IPv4-oriented. A novel parser/runtime escape or a permitted public endpoint that proxies to internal systems remains possible; gVisor, credential removal, strict parsing, and bounded outputs reduce impact. Google Web Risk necessarily receives the complete URL only when enrichment is consented. These limitations must appear in study and release reporting.

Review this model for every provider, fetch-policy, identity, model, Kubernetes, or data-retention change.

