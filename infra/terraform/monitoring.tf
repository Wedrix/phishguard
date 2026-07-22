resource "google_monitoring_uptime_check_config" "web" {
  display_name = "PhishGuard HTTPS health"
  timeout      = "10s"
  period       = "60s"

  monitored_resource {
    type = "uptime_url"
    labels = {
      project_id = var.project_id
      host       = var.domain
    }
  }

  http_check {
    path           = "/healthz"
    port           = 443
    use_ssl        = true
    validate_ssl   = true
    request_method = "GET"
  }

  depends_on = [
    google_dns_record_set.application,
    google_project_service.required["monitoring.googleapis.com"],
  ]
}

resource "google_monitoring_alert_policy" "availability" {
  display_name = "PhishGuard availability"
  combiner     = "OR"

  conditions {
    display_name = "HTTPS check is failing"
    condition_threshold {
      filter          = "metric.type=\"monitoring.googleapis.com/uptime_check/check_passed\" AND resource.type=\"uptime_url\""
      comparison      = "COMPARISON_LT"
      threshold_value = 1
      duration        = "120s"
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_NEXT_OLDER"
      }
    }
  }

  documentation {
    mime_type = "text/markdown"
    content   = "Follow `docs/runbooks/incident-response.md`; check Gateway, web rollout, and `/readyz` without logging submitted URLs."
  }

  depends_on = [google_project_service.required["monitoring.googleapis.com"]]
}

resource "google_monitoring_alert_policy" "database_cpu" {
  display_name = "PhishGuard Cloud SQL CPU saturation"
  combiner     = "OR"

  conditions {
    display_name = "Database CPU above 80%"
    condition_threshold {
      filter          = "metric.type=\"cloudsql.googleapis.com/database/cpu/utilization\" AND resource.type=\"cloudsql_database\" AND resource.label.database_id=\"${var.project_id}:${google_sql_database_instance.main.name}\""
      comparison      = "COMPARISON_GT"
      threshold_value = 0.8
      duration        = "300s"
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_MEAN"
      }
    }
  }

  documentation {
    mime_type = "text/markdown"
    content   = "Inspect slow queries, connections, and job concurrency before changing the database tier."
  }

  depends_on = [google_project_service.required["monitoring.googleapis.com"]]
}
