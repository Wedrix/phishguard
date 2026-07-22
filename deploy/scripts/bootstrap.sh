#!/bin/sh
set -eu

: "${PROJECT_ID:?PROJECT_ID is required}"
REGION=${REGION:-africa-south1}
TF_DIR=$(CDPATH= cd -- "$(dirname "$0")/../../infra/terraform" && pwd)
STATE_BUCKET="${PROJECT_ID}-phishguard-tfstate"

for command in gcloud terraform openssl; do
  command -v "$command" >/dev/null 2>&1 || { echo "$command is required" >&2; exit 2; }
done
case "$PROJECT_ID" in (*[!a-z0-9-]*|'') echo "invalid PROJECT_ID" >&2; exit 2;; esac

gcloud config set project "$PROJECT_ID" >/dev/null
gcloud services enable \
  cloudresourcemanager.googleapis.com \
  secretmanager.googleapis.com \
  serviceusage.googleapis.com \
  storage.googleapis.com \
  --project "$PROJECT_ID"

if ! gcloud storage buckets describe "gs://${STATE_BUCKET}" --project "$PROJECT_ID" >/dev/null 2>&1; then
  gcloud storage buckets create "gs://${STATE_BUCKET}" --project "$PROJECT_ID" --location "$REGION" --uniform-bucket-level-access
  gcloud storage buckets update "gs://${STATE_BUCKET}" --versioning
fi

terraform -chdir="$TF_DIR" init -reconfigure \
  -backend-config="bucket=${STATE_BUCKET}" \
  -backend-config="prefix=demo"

for name in \
  app-hmac-key db-migrator-password web-risk-api-key mtls-ca-cert mtls-client-cert mtls-client-key mtls-server-cert mtls-server-key; do
  if ! gcloud secrets describe "phishguard-${name}" --project "$PROJECT_ID" >/dev/null 2>&1; then
    gcloud secrets create "phishguard-${name}" --project "$PROJECT_ID" --replication-policy=automatic --labels=application=phishguard,environment=demo
  fi
done

tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT INT TERM
umask 077

secret_has_version() {
  test -n "$(gcloud secrets versions list "$1" --project "$PROJECT_ID" --filter='state=ENABLED' --limit=1 --format='value(name)')"
}

if ! secret_has_version phishguard-app-hmac-key; then
  openssl rand -base64 32 >"$tmp_dir/hmac"
  gcloud secrets versions add phishguard-app-hmac-key --project "$PROJECT_ID" --data-file="$tmp_dir/hmac" >/dev/null
fi

if ! secret_has_version phishguard-db-migrator-password; then
  openssl rand -hex 32 >"$tmp_dir/db-migrator-password"
  gcloud secrets versions add phishguard-db-migrator-password --project "$PROJECT_ID" --data-file="$tmp_dir/db-migrator-password" >/dev/null
fi

if test -n "${WEB_RISK_API_KEY:-}" && ! secret_has_version phishguard-web-risk-api-key; then
  printf '%s' "$WEB_RISK_API_KEY" >"$tmp_dir/web-risk"
  gcloud secrets versions add phishguard-web-risk-api-key --project "$PROJECT_ID" --data-file="$tmp_dir/web-risk" >/dev/null
fi

if ! secret_has_version phishguard-mtls-ca-cert || test "${ROTATE_MTLS:-false}" = true; then
  openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 365 \
    -subj '/CN=PhishGuard internal CA' \
    -keyout "$tmp_dir/ca.key" -out "$tmp_dir/ca.crt" >/dev/null 2>&1

  openssl req -newkey rsa:2048 -nodes -sha256 -subj '/CN=jobs' \
    -keyout "$tmp_dir/client.key" -out "$tmp_dir/client.csr" >/dev/null 2>&1
  printf '%s\n' 'extendedKeyUsage=clientAuth' >"$tmp_dir/client.ext"
  openssl x509 -req -sha256 -days 180 -in "$tmp_dir/client.csr" \
    -CA "$tmp_dir/ca.crt" -CAkey "$tmp_dir/ca.key" -CAcreateserial \
    -extfile "$tmp_dir/client.ext" -out "$tmp_dir/client.crt" >/dev/null 2>&1

  openssl req -newkey rsa:2048 -nodes -sha256 -subj '/CN=fetcher.phishguard-demo.svc.cluster.local' \
    -keyout "$tmp_dir/server.key" -out "$tmp_dir/server.csr" >/dev/null 2>&1
  printf '%s\n' \
    'subjectAltName=DNS:fetcher,DNS:fetcher.phishguard-demo,DNS:fetcher.phishguard-demo.svc,DNS:fetcher.phishguard-demo.svc.cluster.local' \
    'extendedKeyUsage=serverAuth' >"$tmp_dir/server.ext"
  openssl x509 -req -sha256 -days 180 -in "$tmp_dir/server.csr" \
    -CA "$tmp_dir/ca.crt" -CAkey "$tmp_dir/ca.key" -CAcreateserial \
    -extfile "$tmp_dir/server.ext" -out "$tmp_dir/server.crt" >/dev/null 2>&1

  for item in \
    "mtls-ca-cert:$tmp_dir/ca.crt" \
    "mtls-client-cert:$tmp_dir/client.crt" \
    "mtls-client-key:$tmp_dir/client.key" \
    "mtls-server-cert:$tmp_dir/server.crt" \
    "mtls-server-key:$tmp_dir/server.key"; do
    secret_name=${item%%:*}
    secret_file=${item#*:}
    gcloud secrets versions add "phishguard-${secret_name}" --project "$PROJECT_ID" --data-file="$secret_file" >/dev/null
  done
fi

echo "Bootstrap complete. Run make deploy PROJECT_ID=${PROJECT_ID} DOMAIN=..."
