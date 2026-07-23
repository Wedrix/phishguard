# Deployment runbook

## One-time setup

1. Create/select a billed Google Cloud project and a Cloud DNS managed zone containing the application domain.
2. Authenticate `gcloud auth application-default login`; install `gcloud`, Terraform ≥1.8, OpenSSL, Docker, and `kubectl`.
3. Run `make bootstrap PROJECT_ID=...`. Store the state-bucket name and Terraform outputs in the project operations record. Bootstrap creates the migrator password directly in Secret Manager; the plaintext never enters Terraform state.
4. Ensure the deploying operator can administer Cloud SQL users and can act as `phishguard-cloud-build@PROJECT_ID.iam.gserviceaccount.com`.
5. Export `WEB_RISK_API_KEY` and run `make deploy PROJECT_ID=... DOMAIN=...`. Pass `DNS_ZONE=...` only if automatic containing-zone discovery is ambiguous. The deploy command creates the built-in `phishguard_migrator` user from the bootstrap secret without putting its password in process arguments, then submits Cloud Build with the dedicated build service account.

## Identity Platform and TOTP

Terraform configures the security-critical Identity Platform baseline; branding, support email, recovery policy, and verification remain operator-reviewed:

1. Confirm Terraform enabled Identity Platform Email/Password and TOTP MFA and authorized only the deployed and project Firebase domains. Do not enable SMS as a silent fallback.
2. Configure recovery email templates, branding, and support address; test verification, recovery, TOTP enrolment, revoked sessions, and recent-auth enforcement with non-privileged test accounts.
3. Keep server verification bound to `IDENTITY_PROJECT_ID`; the deploy workflow injects the public Firebase configuration into the frontend build.
4. Have the intended canonical Administrator complete email verification, TOTP enrolment, and one normal sign-in so an assured `user_account` exists. Obtain the account's immutable Identity Platform subject through an authorised operator workflow; never use an email address as the lookup key.
5. After migration, run the following once from the trusted application image with the web workload's database identity and HMAC key. Do not run it in the fetcher or with an unreviewed local database configuration:

   ```sh
   python -m phishguard.cli bootstrap-admin --subject <identity-platform-subject>
   ```

   The subject is used only to locate the existing account and is excluded from audit detail and application logs. The command refuses a missing, disabled, unverified, non-TOTP account or any database that already has a canonical Administrator. It atomically designates the existing account, appends `user.bootstrap_canonical_admin` to the HMAC chain with a null application actor, and prints a correlation ID. Record the authenticated operator, change approval, timestamp, image digest, target application user UUID, and correlation ID in the operations record. Do not record the email, Identity Platform subject, token, or TOTP secret.
6. Sign in again as the canonical Administrator, because governance changes revoke affected sessions. Verify the account is visibly canonical, the user/role-request administration views are authorized, another Administrator cannot change the canonical account, and the chained event is present before closing bootstrap evidence.

### Canonical Administrator transfer

Treat transfer as a scheduled privileged change, not routine in-application role editing:

1. Confirm the replacement has an existing active, email-verified, TOTP-verified account and has successfully signed in immediately before the change. Resolve the current and replacement Identity Platform subjects through an authorised operator workflow, and record only their application user UUIDs with the current image/schema versions, audit-chain head, backup/PITR point, operator, approval, and rollback owner. Ensure the accounts are distinct.
2. Keep a separate active, assured recovery candidate available when practical. The transfer disables and demotes the former canonical account, so a replacement who cannot authenticate cannot use the application to re-enable it.
3. Run from the trusted application image with the web workload's database identity and HMAC key:

   ```sh
   python -m phishguard.cli transfer-canonical-admin \
     --current-subject <canonical-identity-subject> \
     --replacement-subject <replacement-identity-subject> \
     --confirm-transfer
   ```

   Subjects are lookup-only and are excluded from audit detail and application logs. The command refuses an incorrect current canonical subject, identical subjects, an unqualified replacement, or omission of `--confirm-transfer`. On success it atomically makes the replacement the sole canonical Administrator, demotes the former canonical account to `REGISTERED_USER`, disables it, revokes both users' application sessions, appends `user.transfer_canonical_admin`, and prints a correlation ID.
4. Require a new sign-in from the replacement. Verify canonical status, privileged access, denial for the former account, exactly one canonical account, both users' old sessions revoked, and audit-chain continuity. Stop and invoke the rollback procedure if any check fails; never repair the canonical marker with ad-hoc SQL.

Terraform creates the Firebase web API key and restricts it to `identitytoolkit.googleapis.com`, `securetoken.googleapis.com`, and the deployed HTTPS referrer. The deploy script passes its public web configuration into the Vite build; it is not a secret. If building outside that workflow, supply `VITE_FIREBASE_API_KEY`, `VITE_FIREBASE_AUTH_DOMAIN`, and `VITE_FIREBASE_PROJECT_ID` as Docker build arguments and preserve equivalent API/referrer restrictions.

## Database migration identity

The migration Job uses the dedicated `migrate` Kubernetes/GCP service accounts and a built-in database user. It is the only workload that can mount `phishguard-db-migrator-password`; web and jobs continue using Cloud SQL IAM authentication. On a fresh PostgreSQL 15+ database the job grants schema access to `cloudsqlsuperuser` before Alembic, then grants only connect, schema usage, table DML, and sequence access to the web and jobs IAM roles. It revokes direct update/delete access on `audit_event`, `evidence_observation`, `decision`, and `review_case_event`, and revokes public schema creation. Runtime code retains insert/select access; retention cleanup deletes parent scans and analysis runs, allowing PostgreSQL foreign-key cascades to remove their immutable child rows without granting direct mutation rights.

To rotate the migrator credential, add a new Secret Manager version and set the Cloud SQL user's password from the same value using a protected `--flags-file`; never pass it with `--password=...`. Redeploy only after the secret and database user agree.

## Release and rollback

Pull-request Cloud Build triggers use `cloudbuild.ci.yaml` and select `phishguard-cloud-build-ci@PROJECT_ID.iam.gserviceaccount.com`. That configuration can test and build local images but contains no push or deploy step. The `main` trigger uses `cloudbuild.yaml`, selects `phishguard-cloud-build@PROJECT_ID.iam.gserviceaccount.com`, requires manual approval, and sets `_DEPLOY=true`; manual release submissions select that deployment account explicitly too. Never run untrusted pull-request code with the deployment account. Deployments use image digests and wait for the managed certificate to report `ACTIVE` and Gateway `web` to report `Programmed` before the HTTPS health smoke test. Confirm migration completion, three rollouts, `/healthz`, `/readyz`, and a local-only smoke scan before approval evidence is closed.

### Privileged-governance rollout

1. Before deployment, archive the current app/fetcher digests, Alembic revision, approved model/policy pointers, active Administrator inventory, audit-chain head, and a recoverable database point. Do not claim a backup is usable unless the restoration runbook has been rehearsed.
2. Apply the additive migration while application replicas are held at zero through the existing deploy workflow, then deploy the digest-pinned compatible application. For an existing database, designate the intended canonical account with `bootstrap-admin` before exercising delegated administration; do not leave ordinary operations indefinitely without a canonical account.
3. Exercise, with dedicated test accounts, requested-role creation/cancellation, approval/rejection, privileged-assurance denial, delegated-Administrator appointment, forbidden self/canonical modification, affected-session revocation, idempotent replay, and chained audit entries. A repository test is not evidence that the live Identity Platform tenant behaved correctly.
4. Monitor authentication/authorization failures and privileged audit events through the observation window. Close the change only after the RTM links dated evidence; leave manual accessibility and transfer rehearsal marked pending until actually performed.

### Application rollback

Rollback by redeploying the previous app/fetcher digests and restoring the preceding approved model/policy pointer. Migrations are forward-only and must remain compatible with one prior application version; do not reverse schema changes during the first response.

The privileged-governance migration and its audit/request rows remain in place. Before a planned rollback, the canonical Administrator must review pending requests and explicitly decide which delegated Administrators remain authorized. The preceding application does not understand role requests or canonical transfer and cannot administer already-appointed Administrators; rolling back the image therefore does **not** undo authority already granted. If a delegated role must be removed after an emergency rollback, roll forward to the compatible governance image and perform the audited transition rather than editing PostgreSQL directly.

To reverse a completed canonical transfer, first have the new canonical Administrator re-enable and reappoint the former account as an active, assured non-canonical Administrator, then run a new, separately approved `transfer-canonical-admin` operation with the current and replacement subjects reversed. This is a new audited change, not deletion of the earlier event. If the replacement cannot authenticate, transfer to a prequalified recovery candidate. If no qualified candidate exists, declare an access-control incident and restore through the approved database recovery process; do not bypass constraints or rewrite the audit chain. The absence of an independent break-glass path is recorded as technical debt.

For a governed evaluation, place the approved CSV at `gs://PROJECT_ID-phishguard-research/research/input.csv`. Set the paired ECE and Brier limits approved in the SRS/RTM and create the one-off job:

```sh
kubectl -n phishguard-demo patch configmap app-config --type merge \
  -p "{\"data\":{\"EVALUATION_MAX_ECE\":\"$APPROVED_MAX_ECE\",\"EVALUATION_MAX_BRIER\":\"$APPROVED_MAX_BRIER\"}}"
kubectl -n phishguard-demo create job --from=cronjob/evaluate \
  "evaluate-$(date -u +%Y%m%d%H%M%S)"
```

Both values are optional, but they must be supplied together. Do not invent limits when they are absent: the evaluator will record metrics but select no candidate. Remove the two ConfigMap keys after the governed run if they should not apply to subsequent jobs. The report directory is written under `research/outputs/`; record its object generation and hashes in the experiment manifest.

## Monitoring completion

Terraform creates HTTPS availability and Cloud SQL CPU policies. Before acceptance, attach reviewed notification channels and create URL-free metrics/alerts for web 5xx/latency, job depth and oldest age, provider failures/429s, fetcher denials/timeouts, partial evidence, pod restarts, database connections/storage, and failed or stale backups. Exercise one alert and archive the notification evidence.

Rotate mTLS with `ROTATE_MTLS=true make bootstrap PROJECT_ID=...`, then redeploy immediately so CSI and the fetcher secret converge on the new CA. Verify jobs-to-fetcher mTLS before re-enabling enrichment.
