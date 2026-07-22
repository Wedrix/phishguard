variable "project_id" {
  description = "Existing Google Cloud project ID."
  type        = string
}

variable "region" {
  description = "Regional location for the demo environment."
  type        = string
  default     = "africa-south1"
}

variable "domain" {
  description = "Public DNS name for PhishGuard."
  type        = string
}

variable "dns_zone" {
  description = "Name of an existing Cloud DNS managed zone containing domain."
  type        = string
}

variable "network_cidr" {
  type    = string
  default = "10.20.0.0/20"
}

variable "pods_cidr" {
  type    = string
  default = "10.21.0.0/16"
}

variable "services_cidr" {
  type    = string
  default = "10.22.0.0/20"
}

variable "service_peering_prefix_length" {
  type    = number
  default = 16
}

variable "database_tier" {
  description = "Small demo tier; increase only after measuring saturation."
  type        = string
  default     = "db-custom-1-3840"
}

variable "labels" {
  type = map(string)
  default = {
    application = "phishguard"
    environment = "demo"
    managed-by  = "terraform"
  }
}

