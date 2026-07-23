#!/bin/sh
set -eu

: "${PROJECT_ID:?PROJECT_ID is required}"
: "${DOMAIN:?DOMAIN is required}"
REGION=${REGION:-africa-south1}
TAG=${TAG:-$(date -u +%Y%m%d%H%M%S)}
ROOT_DIR=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
TF_DIR="$ROOT_DIR/infra/terraform"
KUSTOMIZE_OVERLAY=${KUSTOMIZE_OVERLAY:-demo}

case "$PROJECT_ID" in (*[!a-z0-9-]*|'') echo "invalid PROJECT_ID" >&2; exit 2;; esac
case "$DOMAIN" in (*[!A-Za-z0-9.-]*|'') echo "invalid DOMAIN" >&2; exit 2;; esac
case "$KUSTOMIZE_OVERLAY" in (demo|demo-model) :;; (*) echo "KUSTOMIZE_OVERLAY must be demo or demo-model" >&2; exit 2;; esac

tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT INT TERM
umask 077

ensure_database_migrator() {
  migrator_user=phishguard_migrator
  if test -z "$(gcloud sql users list --instance phishguard-demo --project "$PROJECT_ID" --filter="name=${migrator_user}" --limit=1 --format='value(name)')"; then
    password_file="$tmp_dir/db-migrator-password"
    flags_file="$tmp_dir/db-migrator-user-flags.yaml"
    gcloud secrets versions access latest --secret phishguard-db-migrator-password --project "$PROJECT_ID" >"$password_file"
    {
      printf '%s\n' '--instance: phishguard-demo'
      printf '%s' '--password: '
      tr -d '\r\n' <"$password_file"
      printf '\n%s\n' '--type: BUILT_IN'
    } >"$flags_file"
    gcloud sql users create "$migrator_user" --project "$PROJECT_ID" --flags-file="$flags_file" --quiet >/dev/null
    rm -f "$password_file" "$flags_file"
  fi
}

if test -z "${APP_IMAGE:-}" || test -z "${FETCHER_IMAGE:-}"; then
  for command in gcloud terraform; do
    command -v "$command" >/dev/null 2>&1 || { echo "$command is required" >&2; exit 2; }
  done

  if test -z "${DNS_ZONE:-}"; then
    best_length=0
    for candidate in $(gcloud dns managed-zones list --project "$PROJECT_ID" --format='value(name)'); do
      dns_name=$(gcloud dns managed-zones describe "$candidate" --project "$PROJECT_ID" --format='value(dnsName)')
      case "${DOMAIN}." in
        *"$dns_name")
          if test "${#dns_name}" -gt "$best_length"; then
            DNS_ZONE=$candidate
            best_length=${#dns_name}
          fi
          ;;
      esac
    done
  fi
  : "${DNS_ZONE:?No containing Cloud DNS managed zone found; pass DNS_ZONE explicitly}"

  STATE_BUCKET="${PROJECT_ID}-phishguard-tfstate"
  terraform -chdir="$TF_DIR" init -reconfigure \
    -backend-config="bucket=${STATE_BUCKET}" \
    -backend-config="prefix=demo"
  terraform -chdir="$TF_DIR" apply -auto-approve \
    -var="project_id=${PROJECT_ID}" \
    -var="region=${REGION}" \
    -var="domain=${DOMAIN}" \
    -var="dns_zone=${DNS_ZONE}"
  firebase_api_key=$(terraform -chdir="$TF_DIR" output -raw firebase_api_key)
  firebase_auth_domain=$(terraform -chdir="$TF_DIR" output -raw firebase_auth_domain)
  cloud_build_service_account=$(terraform -chdir="$TF_DIR" output -raw cloud_build_service_account)
  cloud_build_source_bucket=$(terraform -chdir="$TF_DIR" output -raw cloud_build_source_bucket)

  ensure_database_migrator

  if test -z "$(gcloud secrets versions list phishguard-web-risk-api-key --project "$PROJECT_ID" --filter='state=ENABLED' --limit=1 --format='value(name)')"; then
    : "${WEB_RISK_API_KEY:?Export WEB_RISK_API_KEY before the first deployment}"
    key_file="$tmp_dir/web-risk-api-key"
    printf '%s' "$WEB_RISK_API_KEY" >"$key_file"
    gcloud secrets versions add phishguard-web-risk-api-key --project "$PROJECT_ID" --data-file="$key_file" >/dev/null
  fi

  gcloud builds submit "$ROOT_DIR" \
    --project "$PROJECT_ID" \
    --config "$ROOT_DIR/cloudbuild.yaml" \
    --service-account="projects/${PROJECT_ID}/serviceAccounts/${cloud_build_service_account}" \
    --gcs-source-staging-dir="gs://${cloud_build_source_bucket}/source" \
    --substitutions="_REGION=${REGION},_DOMAIN=${DOMAIN},_DEPLOY=true,_TAG=${TAG},_OVERLAY=${KUSTOMIZE_OVERLAY},_FIREBASE_API_KEY=${firebase_api_key},_FIREBASE_AUTH_DOMAIN=${firebase_auth_domain},_FIREBASE_PROJECT_ID=${PROJECT_ID}"
  exit 0
fi

for command in curl gcloud kubectl; do
  command -v "$command" >/dev/null 2>&1 || { echo "$command is required" >&2; exit 2; }
done

gcloud container clusters get-credentials phishguard-demo --project "$PROJECT_ID" --region "$REGION"
if test -n "${CLOUD_SQL_CONNECTION_NAME:-}"; then
  connection_name=$CLOUD_SQL_CONNECTION_NAME
else
  command -v terraform >/dev/null 2>&1 || { echo "terraform or CLOUD_SQL_CONNECTION_NAME is required" >&2; exit 2; }
  connection_name=$(terraform -chdir="$TF_DIR" output -raw cloud_sql_connection_name)
fi
kms_key_name=${KMS_KEY_NAME:-projects/${PROJECT_ID}/locations/${REGION}/keyRings/phishguard-demo/cryptoKeys/url-encryption}

kubectl apply -f "$ROOT_DIR/deploy/k8s/base/namespace.yaml"

gcloud secrets versions access latest --project "$PROJECT_ID" --secret phishguard-mtls-ca-cert >"$tmp_dir/ca.crt"
gcloud secrets versions access latest --project "$PROJECT_ID" --secret phishguard-mtls-server-cert >"$tmp_dir/tls.crt"
gcloud secrets versions access latest --project "$PROJECT_ID" --secret phishguard-mtls-server-key >"$tmp_dir/tls.key"
# ponytail: CRC marker can collide; use SHA-256 if certificate rotations become frequent.
mtls_version=$(cksum "$tmp_dir/ca.crt" | awk '{print $1}')
kubectl -n phishguard-demo create secret generic fetcher-mtls \
  --from-file=ca.crt="$tmp_dir/ca.crt" \
  --from-file=tls.crt="$tmp_dir/tls.crt" \
  --from-file=tls.key="$tmp_dir/tls.key" \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl kustomize "$ROOT_DIR/deploy/k8s/overlays/${KUSTOMIZE_OVERLAY}" | sed \
  -e "s|APP_IMAGE|${APP_IMAGE}|g" \
  -e "s|FETCHER_IMAGE|${FETCHER_IMAGE}|g" \
  -e "s|__PROJECT_ID__|${PROJECT_ID}|g" \
  -e "s|PHISHGUARD_DOMAIN|${DOMAIN}|g" \
  -e "s|__CLOUD_SQL_CONNECTION_NAME__|${connection_name}|g" \
  -e "s|MODEL_BUCKET|${PROJECT_ID}-phishguard-models|g" \
  -e "s|RESEARCH_BUCKET|${PROJECT_ID}-phishguard-research|g" \
  -e "s|__KMS_KEY_NAME__|${kms_key_name}|g" >"$tmp_dir/rendered.yaml"

if grep -Eq 'APP_IMAGE|FETCHER_IMAGE|__PROJECT_ID__|PHISHGUARD_DOMAIN|__CLOUD_SQL_CONNECTION_NAME__|MODEL_BUCKET|RESEARCH_BUCKET|__KMS_KEY_NAME__' "$tmp_dir/rendered.yaml"; then
  echo "unresolved deployment placeholder" >&2
  exit 1
fi
grep -q "IDENTITY_PROJECT_ID: ${PROJECT_ID}" "$tmp_dir/rendered.yaml" || { echo "Identity Platform project ID is missing" >&2; exit 1; }
grep -q 'port: 3307' "$tmp_dir/rendered.yaml" || { echo "Cloud SQL private egress rule is missing" >&2; exit 1; }

kubectl -n phishguard-demo delete job migrate --ignore-not-found
sed 's/^  replicas: 1$/  replicas: 0/' "$tmp_dir/rendered.yaml" >"$tmp_dir/pre-migration.yaml"
kubectl apply -f "$tmp_dir/pre-migration.yaml"
kubectl -n phishguard-demo wait --for=condition=complete job/migrate --timeout=10m
kubectl apply -f "$tmp_dir/rendered.yaml"
kubectl -n phishguard-demo set env deployment/jobs --containers=app "PHISHGUARD_MTLS_VERSION=${mtls_version}"
kubectl -n phishguard-demo set env deployment/fetcher --containers=fetcher "PHISHGUARD_MTLS_VERSION=${mtls_version}"
kubectl -n phishguard-demo rollout status deployment/fetcher --timeout=10m
kubectl -n phishguard-demo rollout status deployment/jobs --timeout=10m
kubectl -n phishguard-demo rollout status deployment/web --timeout=10m

certificate_attempt=0
certificate_state=
while test "$certificate_attempt" -lt 120; do
  certificate_state=$(gcloud certificate-manager certificates describe phishguard-demo \
    --project "$PROJECT_ID" \
    --location global \
    --format='value(managed.state)' 2>/dev/null || :)
  test "$certificate_state" = ACTIVE && break
  certificate_attempt=$((certificate_attempt + 1))
  sleep 10
done
test "$certificate_state" = ACTIVE || {
  echo "certificate phishguard-demo did not become ACTIVE (last state: ${certificate_state:-unavailable})" >&2
  exit 1
}

kubectl -n phishguard-demo wait --for=condition=Programmed gateway/web --timeout=15m
curl --fail --silent --show-error --retry 12 --retry-delay 10 "https://${DOMAIN}/healthz" >/dev/null

echo "Deployed ${APP_IMAGE} and ${FETCHER_IMAGE} to https://${DOMAIN}"
