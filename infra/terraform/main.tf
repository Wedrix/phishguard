locals {
  name                   = "phishguard-demo"
  network_name           = "${local.name}-v2"
  database_instance_name = "${local.name}-v2"
  apis = toset([
    "artifactregistry.googleapis.com",
    "apikeys.googleapis.com",
    "certificatemanager.googleapis.com",
    "cloudbuild.googleapis.com",
    "cloudkms.googleapis.com",
    "compute.googleapis.com",
    "container.googleapis.com",
    "dns.googleapis.com",
    "iam.googleapis.com",
    "iamcredentials.googleapis.com",
    "identitytoolkit.googleapis.com",
    "logging.googleapis.com",
    "monitoring.googleapis.com",
    "secretmanager.googleapis.com",
    "securetoken.googleapis.com",
    "servicenetworking.googleapis.com",
    "sqladmin.googleapis.com",
    "sts.googleapis.com",
    "storage.googleapis.com",
    "webrisk.googleapis.com",
  ])
}

resource "google_apikeys_key" "firebase_web" {
  name         = "phishguard-web"
  display_name = "PhishGuard Identity Platform web client"

  restrictions {
    browser_key_restrictions {
      allowed_referrers = ["https://${var.domain}", "https://${var.domain}/*"]
    }
    api_targets {
      service = "identitytoolkit.googleapis.com"
    }
    api_targets {
      service = "securetoken.googleapis.com"
    }
  }

  depends_on = [google_project_service.required]
}

resource "google_project_service" "required" {
  for_each           = local.apis
  project            = var.project_id
  service            = each.value
  disable_on_destroy = false
}

resource "google_identity_platform_config" "default" {
  project = var.project_id

  authorized_domains = [
    var.domain,
    "${var.project_id}.firebaseapp.com",
  ]

  sign_in {
    allow_duplicate_emails = false

    email {
      enabled           = true
      password_required = true
    }
  }

  mfa {
    state = "ENABLED"

    provider_configs {
      state = "ENABLED"

      totp_provider_config {
        adjacent_intervals = 1
      }
    }
  }

  depends_on = [google_project_service.required]
}

resource "google_compute_network" "main" {
  name                    = local.network_name
  auto_create_subnetworks = false
  depends_on              = [google_project_service.required]
}

resource "google_compute_subnetwork" "main" {
  name                     = local.network_name
  region                   = var.region
  network                  = google_compute_network.main.id
  ip_cidr_range            = var.network_cidr
  private_ip_google_access = true

  secondary_ip_range {
    range_name    = "pods"
    ip_cidr_range = var.pods_cidr
  }

  secondary_ip_range {
    range_name    = "services"
    ip_cidr_range = var.services_cidr
  }
}

resource "google_compute_router" "main" {
  name    = local.name
  region  = var.region
  network = google_compute_network.main.id
}

resource "google_compute_address" "nat" {
  name   = "${local.name}-nat"
  region = var.region

  depends_on = [google_project_service.required["compute.googleapis.com"]]
}

resource "google_compute_router_nat" "main" {
  name                               = local.name
  router                             = google_compute_router.main.name
  region                             = var.region
  nat_ip_allocate_option             = "MANUAL_ONLY"
  nat_ips                            = [google_compute_address.nat.self_link]
  source_subnetwork_ip_ranges_to_nat = "LIST_OF_SUBNETWORKS"

  subnetwork {
    name                    = google_compute_subnetwork.main.id
    source_ip_ranges_to_nat = ["ALL_IP_RANGES"]
  }

  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
}

resource "google_compute_global_address" "private_services" {
  name          = "${local.network_name}-services"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = var.service_peering_prefix_length
  network       = google_compute_network.main.id
}

resource "google_service_networking_connection" "private_services" {
  network                 = google_compute_network.main.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.private_services.name]
  depends_on              = [google_project_service.required]
}

resource "google_artifact_registry_repository" "images" {
  location      = var.region
  repository_id = "phishguard"
  format        = "DOCKER"
  description   = "Digest-pinned PhishGuard application images"
  labels        = var.labels
  depends_on    = [google_project_service.required]
}

resource "google_storage_bucket" "build_source" {
  name                        = "${var.project_id}-phishguard-build-source"
  location                    = upper(var.region)
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  labels                      = merge(var.labels, { content = "build-source" })

  lifecycle_rule {
    condition {
      age = 7
    }
    action {
      type = "Delete"
    }
  }

  depends_on = [google_project_service.required["storage.googleapis.com"]]
}

resource "google_storage_bucket" "artifacts" {
  for_each                    = toset(["models", "research"])
  name                        = "${var.project_id}-phishguard-${each.value}"
  location                    = upper(var.region)
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  labels                      = merge(var.labels, { content = each.value })

  versioning {
    enabled = true
  }

  retention_policy {
    retention_period = 2592000
    is_locked        = false
  }

  lifecycle_rule {
    condition {
      num_newer_versions = 10
    }
    action {
      type = "Delete"
    }
  }

  depends_on = [google_project_service.required["storage.googleapis.com"]]
}

resource "google_kms_key_ring" "main" {
  name     = local.name
  location = var.region
  depends_on = [
    google_project_service.required,
  ]
}

resource "google_kms_crypto_key" "urls" {
  name            = "url-encryption"
  key_ring        = google_kms_key_ring.main.id
  rotation_period = "7776000s"

  lifecycle {
    prevent_destroy = true
  }
}

data "google_secret_manager_secret" "runtime" {
  for_each = toset([
    "app-hmac-key",
    "db-migrator-password",
    "web-risk-api-key",
    "mtls-ca-cert",
    "mtls-client-cert",
    "mtls-client-key",
    "mtls-server-cert",
    "mtls-server-key",
  ])

  secret_id = "phishguard-${each.value}"
  project   = var.project_id

  depends_on = [google_project_service.required["secretmanager.googleapis.com"]]
}

resource "google_sql_database_instance" "main" {
  name                = local.database_instance_name
  region              = var.region
  database_version    = "POSTGRES_16"
  deletion_protection = true

  settings {
    tier              = var.database_tier
    edition           = "ENTERPRISE"
    availability_type = "ZONAL"
    disk_type         = "PD_SSD"
    disk_autoresize   = true
    disk_size         = 20
    user_labels       = var.labels

    database_flags {
      name  = "cloudsql.iam_authentication"
      value = "on"
    }

    ip_configuration {
      ipv4_enabled                                  = false
      private_network                               = google_compute_network.main.id
      enable_private_path_for_google_cloud_services = true
    }

    backup_configuration {
      enabled                        = true
      point_in_time_recovery_enabled = true
      start_time                     = "02:00"
      transaction_log_retention_days = 7

      backup_retention_settings {
        retained_backups = 30
        retention_unit   = "COUNT"
      }
    }

    maintenance_window {
      day          = 7
      hour         = 3
      update_track = "stable"
    }
  }

  depends_on = [google_service_networking_connection.private_services]
}

resource "google_sql_database" "main" {
  name     = "phishguard"
  instance = google_sql_database_instance.main.name
}

resource "google_container_cluster" "main" {
  name                = local.name
  location            = var.region
  network             = google_compute_network.main.id
  subnetwork          = google_compute_subnetwork.main.id
  enable_autopilot    = true
  deletion_protection = true
  networking_mode     = "VPC_NATIVE"
  resource_labels     = var.labels

  release_channel {
    channel = "REGULAR"
  }

  ip_allocation_policy {
    cluster_secondary_range_name  = "pods"
    services_secondary_range_name = "services"
  }

  private_cluster_config {
    enable_private_nodes    = true
    enable_private_endpoint = false
    master_ipv4_cidr_block  = "172.16.0.0/28"
  }

  workload_identity_config {
    workload_pool = "${var.project_id}.svc.id.goog"
  }

  gateway_api_config {
    channel = "CHANNEL_STANDARD"
  }

  secret_manager_config {
    enabled = true
  }

  addons_config {
    gcs_fuse_csi_driver_config {
      enabled = true
    }
  }

  monitoring_config {
    enable_components = ["APISERVER", "CONTROLLER_MANAGER", "SCHEDULER", "SYSTEM_COMPONENTS", "STORAGE", "POD", "DEPLOYMENT", "STATEFULSET"]
    managed_prometheus {
      enabled = true
    }
  }

  logging_config {
    enable_components = ["SYSTEM_COMPONENTS", "WORKLOADS", "APISERVER"]
  }

  depends_on = [google_project_service.required]
}
