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
4. Bootstrap the first administrator with the one-time `python -m phishguard.cli bootstrap-admin --subject ... --email ...` operator command. It appends `user.bootstrap_admin` to the HMAC chain in the same transaction as account creation or promotion and prints its generated correlation ID; the null application actor denotes the authenticated out-of-band deployment operator. Record the authenticated operator, timestamp, and correlation ID without copying the email or identity subject into logs. Never add an in-app path that grants Administrator.

Terraform creates the Firebase web API key and restricts it to `identitytoolkit.googleapis.com`, `securetoken.googleapis.com`, and the deployed HTTPS referrer. The deploy script passes its public web configuration into the Vite build; it is not a secret. If building outside that workflow, supply `VITE_FIREBASE_API_KEY`, `VITE_FIREBASE_AUTH_DOMAIN`, and `VITE_FIREBASE_PROJECT_ID` as Docker build arguments and preserve equivalent API/referrer restrictions.

## Database migration identity

The migration Job uses the dedicated `migrate` Kubernetes/GCP service accounts and a built-in database user. It is the only workload that can mount `phishguard-db-migrator-password`; web and jobs continue using Cloud SQL IAM authentication. On a fresh PostgreSQL 15+ database the job grants schema access to `cloudsqlsuperuser` before Alembic, then grants only connect, schema usage, table DML, and sequence access to the web and jobs IAM roles. It revokes direct update/delete access on `audit_event`, `evidence_observation`, `decision`, and `review_case_event`, and revokes public schema creation. Runtime code retains insert/select access; retention cleanup deletes parent scans and analysis runs, allowing PostgreSQL foreign-key cascades to remove their immutable child rows without granting direct mutation rights.

To rotate the migrator credential, add a new Secret Manager version and set the Cloud SQL user's password from the same value using a protected `--flags-file`; never pass it with `--password=...`. Redeploy only after the secret and database user agree.

## Release and rollback

Pull-request Cloud Build triggers use `cloudbuild.ci.yaml` and select `phishguard-cloud-build-ci@PROJECT_ID.iam.gserviceaccount.com`. That configuration can test and build local images but contains no push or deploy step. The `main` trigger uses `cloudbuild.yaml`, selects `phishguard-cloud-build@PROJECT_ID.iam.gserviceaccount.com`, requires manual approval, and sets `_DEPLOY=true`; manual release submissions select that deployment account explicitly too. Never run untrusted pull-request code with the deployment account. Deployments use image digests and wait for the managed certificate to report `ACTIVE` and Gateway `web` to report `Programmed` before the HTTPS health smoke test. Confirm migration completion, three rollouts, `/healthz`, `/readyz`, and a local-only smoke scan before approval evidence is closed.

Rollback by redeploying the previous app/fetcher digests and restoring the preceding approved model/policy pointer. Migrations are forward-only and must remain compatible with one prior application version; do not reverse schema changes during the first response.

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
