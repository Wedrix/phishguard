resource "google_compute_global_address" "ingress" {
  name = local.name

  depends_on = [google_project_service.required["compute.googleapis.com"]]
}

resource "google_compute_security_policy" "web" {
  name        = local.name
  description = "PhishGuard demo edge policy"

  rule {
    action   = "throttle"
    priority = 1000
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
    rate_limit_options {
      conform_action = "allow"
      exceed_action  = "deny(429)"
      enforce_on_key = "IP"
      rate_limit_threshold {
        count        = 120
        interval_sec = 60
      }
    }
  }

  rule {
    action   = "allow"
    priority = 2147483647
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
  }

  depends_on = [google_project_service.required["compute.googleapis.com"]]
}

resource "google_certificate_manager_dns_authorization" "main" {
  name        = local.name
  domain      = var.domain
  description = "PhishGuard certificate DNS authorization"
  depends_on  = [google_project_service.required]
}

resource "google_dns_record_set" "certificate_validation" {
  managed_zone = var.dns_zone
  name         = google_certificate_manager_dns_authorization.main.dns_resource_record[0].name
  type         = google_certificate_manager_dns_authorization.main.dns_resource_record[0].type
  ttl          = 300
  rrdatas      = [google_certificate_manager_dns_authorization.main.dns_resource_record[0].data]
}

resource "google_certificate_manager_certificate" "main" {
  name        = local.name
  description = "Managed certificate for ${var.domain}"
  managed {
    domains            = [var.domain]
    dns_authorizations = [google_certificate_manager_dns_authorization.main.id]
  }
  depends_on = [google_dns_record_set.certificate_validation]
}

resource "google_certificate_manager_certificate_map" "main" {
  name        = local.name
  description = "Certificate map used by the GKE Gateway"

  depends_on = [google_project_service.required["certificatemanager.googleapis.com"]]
}

resource "google_certificate_manager_certificate_map_entry" "main" {
  name         = local.name
  map          = google_certificate_manager_certificate_map.main.name
  certificates = [google_certificate_manager_certificate.main.id]
  hostname     = var.domain
}

resource "google_dns_record_set" "application" {
  managed_zone = var.dns_zone
  name         = "${trimsuffix(var.domain, ".")}."
  type         = "A"
  ttl          = 300
  rrdatas      = [google_compute_global_address.ingress.address]

  depends_on = [google_project_service.required["dns.googleapis.com"]]
}
