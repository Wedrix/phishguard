# Infrastructure

`terraform/` defines the single `phishguard-demo` GCP environment. State is stored in the project bucket created by `deploy/scripts/bootstrap.sh`.

The module deliberately expects an existing project and Cloud DNS managed zone. Cloud SQL and GKE deletion protection are enabled. Disable them explicitly before an intentional teardown; never bypass that protection during incident response.

The artefact bucket uses versioning, a 30-day retention policy, public-access prevention, and create/read-only workload roles. The policy is intentionally not bucket-locked in this disposable demo because locking is irreversible; production governance must approve and lock a suitable retention period.

Terraform also enables Identity Platform email/password sign-in and TOTP MFA, authorizes the configured application domain, enables the Identity Toolkit and Secure Token APIs, and creates a browser-restricted web API key limited to those two APIs. Application roles remain authoritative in PostgreSQL; Identity Platform does not grant PhishGuard roles.

The trusted `web`, `jobs`, and one-shot `migrate` Kubernetes service accounts use separate Workload Identity principals. Web and jobs retain Cloud SQL IAM database authentication. Bootstrap generates the built-in migrator password directly into Secret Manager, outside Terraform state; only the migration principal can mount it, and the deployment creates the corresponding Cloud SQL user through a temporary protected gcloud flags file so the password is not placed in command arguments. The migration user performs schema changes and then grants bounded DML privileges to both IAM-authenticated runtime roles. It revokes direct `UPDATE` and `DELETE` on audit events, evidence observations, decisions, and review-case events; PostgreSQL foreign-key cascades can still remove child rows when the jobs role expires and deletes their parent scan or analysis run. The fetcher has no cloud identity. Secret Manager CSI mounts trusted-workload secrets, while deployment copies only the CA certificate and server certificate/key into the `fetcher-mtls` Kubernetes Secret.

Trusted releases run `cloudbuild.yaml` as the dedicated `phishguard-cloud-build` service account. Its project roles are limited to cluster deployment, Cloud SQL and certificate-state discovery, logging, and service consumption; Artifact Registry write, build-source read, and fetcher mTLS secret access are resource-scoped. Manual submissions explicitly select this account and stage source in its private seven-day bucket. Pull-request triggers instead run `cloudbuild.ci.yaml` as `phishguard-cloud-build-ci`; that account can write logs, consume enabled services, and read only the private build-source bucket, but cannot push images, deploy to GKE, inspect Cloud SQL, or read runtime secrets. Each trigger must select the account named by its configuration. The submitting operator needs `iam.serviceAccounts.actAs` on the applicable account and permission to upload submitted source.

The Autopilot node identity receives Artifact Registry read access only on the PhishGuard repository so digest-pinned workloads can pull their images.

NetworkPolicy is defence in depth, not the primary SSRF control. The fetcher must independently reject disallowed addresses before every connection and after every redirect.

## Verification boundary

The configuration has passed Terraform validation and Kustomize rendering only. It has not been applied to a live project. Cloud SQL daily backup, PITR, 30 retained backups and deletion protection are configured, but restoration has not been rehearsed. GKE Autopilot/gVisor placement, Workload Identity, mTLS, NetworkPolicy egress, managed certificate, Cloud Armor, uptime checks, live Web Risk access and rollback all require verification after deployment.

Do not describe this environment as operational or recovered until the deployment, controlled provider smoke test and timed restore runbooks have produced dated evidence. Load, manual accessibility and user-study evidence are application acceptance work and are likewise still outstanding.
