output "cluster_name" {
  value = google_container_cluster.main.name
}

output "cluster_region" {
  value = google_container_cluster.main.location
}

output "artifact_repository" {
  value = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.images.repository_id}"
}

output "cloud_sql_connection_name" {
  value = google_sql_database_instance.main.connection_name
}

output "kms_key_name" {
  value = google_kms_crypto_key.urls.id
}

output "web_service_account" {
  value = google_service_account.web.email
}

output "jobs_service_account" {
  value = google_service_account.jobs.email
}

output "migrate_service_account" {
  value = google_service_account.migrate.email
}

output "cloud_build_service_account" {
  value = google_service_account.cloud_build.email
}

output "cloud_build_ci_service_account" {
  value = google_service_account.cloud_build_ci.email
}

output "cloud_build_source_bucket" {
  value = google_storage_bucket.build_source.name
}

output "ingress_ip" {
  value = google_compute_global_address.ingress.address
}

output "nat_ip" {
  value = google_compute_address.nat.address
}

output "model_bucket" {
  value = google_storage_bucket.artifacts["models"].name
}

output "research_bucket" {
  value = google_storage_bucket.artifacts["research"].name
}

output "firebase_api_key" {
  value     = google_apikeys_key.firebase_web.key_string
  sensitive = true
}

output "firebase_auth_domain" {
  value = "${var.project_id}.firebaseapp.com"
}
