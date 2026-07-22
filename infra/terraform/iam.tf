resource "google_service_account" "web" {
  account_id   = "phishguard-web"
  display_name = "PhishGuard web workload"
  depends_on   = [google_project_service.required]
}

resource "google_service_account" "jobs" {
  account_id   = "phishguard-jobs"
  display_name = "PhishGuard jobs"
  depends_on   = [google_project_service.required]
}

resource "google_service_account" "migrate" {
  account_id   = "phishguard-migrate"
  display_name = "PhishGuard database migration workload"
  depends_on   = [google_project_service.required]
}

resource "google_service_account" "cloud_build" {
  account_id   = "phishguard-cloud-build"
  display_name = "PhishGuard Cloud Build executor"
  depends_on   = [google_project_service.required]
}

resource "google_service_account" "cloud_build_ci" {
  account_id   = "phishguard-cloud-build-ci"
  display_name = "PhishGuard pull-request CI executor"
  depends_on   = [google_project_service.required]
}

data "google_project" "current" {
  project_id = var.project_id
}

locals {
  cloud_build_roles = toset([
    "roles/certificatemanager.viewer",
    "roles/cloudsql.viewer",
    "roles/container.developer",
    "roles/logging.logWriter",
    "roles/serviceusage.serviceUsageConsumer",
  ])
  cloud_build_ci_roles = toset([
    "roles/logging.logWriter",
    "roles/serviceusage.serviceUsageConsumer",
  ])
}

resource "google_project_iam_member" "cloud_build" {
  for_each = local.cloud_build_roles
  project  = var.project_id
  role     = each.value
  member   = "serviceAccount:${google_service_account.cloud_build.email}"
}

resource "google_project_iam_member" "cloud_build_ci" {
  for_each = local.cloud_build_ci_roles
  project  = var.project_id
  role     = each.value
  member   = "serviceAccount:${google_service_account.cloud_build_ci.email}"
}

resource "google_artifact_registry_repository_iam_member" "cloud_build_writer" {
  location   = google_artifact_registry_repository.images.location
  repository = google_artifact_registry_repository.images.name
  role       = "roles/artifactregistry.writer"
  member     = "serviceAccount:${google_service_account.cloud_build.email}"
}

resource "google_artifact_registry_repository_iam_member" "gke_node_reader" {
  location   = google_artifact_registry_repository.images.location
  repository = google_artifact_registry_repository.images.name
  role       = "roles/artifactregistry.reader"
  member     = "serviceAccount:${data.google_project.current.number}-compute@developer.gserviceaccount.com"
}

resource "google_storage_bucket_iam_member" "cloud_build_source" {
  bucket = google_storage_bucket.build_source.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.cloud_build.email}"
}

resource "google_storage_bucket_iam_member" "cloud_build_ci_source" {
  bucket = google_storage_bucket.build_source.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.cloud_build_ci.email}"
}

resource "google_service_account_iam_member" "cloud_build_service_agent" {
  service_account_id = google_service_account.cloud_build.name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = "serviceAccount:service-${data.google_project.current.number}@gcp-sa-cloudbuild.iam.gserviceaccount.com"
  depends_on         = [google_project_service.required["cloudbuild.googleapis.com"]]
}

resource "google_service_account_iam_member" "cloud_build_ci_service_agent" {
  service_account_id = google_service_account.cloud_build_ci.name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = "serviceAccount:service-${data.google_project.current.number}@gcp-sa-cloudbuild.iam.gserviceaccount.com"
  depends_on         = [google_project_service.required["cloudbuild.googleapis.com"]]
}

resource "google_secret_manager_secret_iam_member" "cloud_build_fetcher_mtls" {
  for_each  = toset(["mtls-ca-cert", "mtls-server-cert", "mtls-server-key"])
  secret_id = data.google_secret_manager_secret.runtime[each.value].id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.cloud_build.email}"
}

locals {
  workload_roles = {
    "web-cloudsql-client"     = [google_service_account.web.email, "roles/cloudsql.client"]
    "web-cloudsql-instance"   = [google_service_account.web.email, "roles/cloudsql.instanceUser"]
    "web-logging"             = [google_service_account.web.email, "roles/logging.logWriter"]
    "web-monitoring"          = [google_service_account.web.email, "roles/monitoring.metricWriter"]
    "jobs-cloudsql-client"    = [google_service_account.jobs.email, "roles/cloudsql.client"]
    "jobs-cloudsql-instance"  = [google_service_account.jobs.email, "roles/cloudsql.instanceUser"]
    "jobs-logging"            = [google_service_account.jobs.email, "roles/logging.logWriter"]
    "jobs-monitoring"         = [google_service_account.jobs.email, "roles/monitoring.metricWriter"]
    "migrate-cloudsql-client" = [google_service_account.migrate.email, "roles/cloudsql.client"]
  }
}

resource "google_project_iam_member" "workloads" {
  for_each = local.workload_roles
  project  = var.project_id
  role     = each.value[1]
  member   = "serviceAccount:${each.value[0]}"
}

locals {
  web_principal     = "principal://iam.googleapis.com/projects/${data.google_project.current.number}/locations/global/workloadIdentityPools/${var.project_id}.svc.id.goog/subject/ns/phishguard-demo/sa/web"
  jobs_principal    = "principal://iam.googleapis.com/projects/${data.google_project.current.number}/locations/global/workloadIdentityPools/${var.project_id}.svc.id.goog/subject/ns/phishguard-demo/sa/jobs"
  migrate_principal = "principal://iam.googleapis.com/projects/${data.google_project.current.number}/locations/global/workloadIdentityPools/${var.project_id}.svc.id.goog/subject/ns/phishguard-demo/sa/migrate"
  csi_secret_access = {
    "web-hmac"            = ["app-hmac-key", local.web_principal]
    "jobs-hmac"           = ["app-hmac-key", local.jobs_principal]
    "jobs-web-risk"       = ["web-risk-api-key", local.jobs_principal]
    "jobs-client-cert"    = ["mtls-client-cert", local.jobs_principal]
    "jobs-client-key"     = ["mtls-client-key", local.jobs_principal]
    "jobs-ca-cert"        = ["mtls-ca-cert", local.jobs_principal]
    "migrate-db-password" = ["db-migrator-password", local.migrate_principal]
  }
}

resource "google_secret_manager_secret_iam_member" "csi" {
  for_each   = local.csi_secret_access
  secret_id  = data.google_secret_manager_secret.runtime[each.value[0]].id
  role       = "roles/secretmanager.secretAccessor"
  member     = each.value[1]
  depends_on = [google_container_cluster.main]
}

resource "google_service_account_iam_member" "web_workload_identity" {
  service_account_id = google_service_account.web.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "serviceAccount:${var.project_id}.svc.id.goog[phishguard-demo/web]"
  depends_on         = [google_container_cluster.main]
}

resource "google_service_account_iam_member" "jobs_workload_identity" {
  service_account_id = google_service_account.jobs.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "serviceAccount:${var.project_id}.svc.id.goog[phishguard-demo/jobs]"
  depends_on         = [google_container_cluster.main]
}

resource "google_service_account_iam_member" "migrate_workload_identity" {
  service_account_id = google_service_account.migrate.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "serviceAccount:${var.project_id}.svc.id.goog[phishguard-demo/migrate]"
  depends_on         = [google_container_cluster.main]
}

resource "google_kms_crypto_key_iam_member" "web" {
  crypto_key_id = google_kms_crypto_key.urls.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${google_service_account.web.email}"
}

resource "google_kms_crypto_key_iam_member" "jobs" {
  crypto_key_id = google_kms_crypto_key.urls.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${google_service_account.jobs.email}"
}

resource "google_storage_bucket_iam_member" "web_artifacts" {
  bucket = google_storage_bucket.artifacts["models"].name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.web.email}"
}

resource "google_storage_bucket_iam_member" "jobs_artifacts_viewer" {
  bucket = google_storage_bucket.artifacts["research"].name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.jobs.email}"
}

resource "google_storage_bucket_iam_member" "jobs_artifacts_creator" {
  bucket = google_storage_bucket.artifacts["research"].name
  role   = "roles/storage.objectCreator"
  member = "serviceAccount:${google_service_account.jobs.email}"
}

resource "google_storage_bucket_iam_member" "jobs_models_viewer" {
  bucket = google_storage_bucket.artifacts["models"].name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.jobs.email}"
}

resource "google_sql_user" "web" {
  name     = trimsuffix(google_service_account.web.email, ".gserviceaccount.com")
  instance = google_sql_database_instance.main.name
  type     = "CLOUD_IAM_SERVICE_ACCOUNT"
}

resource "google_sql_user" "jobs" {
  name     = trimsuffix(google_service_account.jobs.email, ".gserviceaccount.com")
  instance = google_sql_database_instance.main.name
  type     = "CLOUD_IAM_SERVICE_ACCOUNT"
}
