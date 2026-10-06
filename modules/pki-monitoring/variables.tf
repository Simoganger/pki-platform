variable "name_prefix" {
  description = "Prefix for resource names, e.g. \"pki-prod\"."
  type        = string
}

variable "alert_emails" {
  description = "E-mail addresses subscribed to the PKI alert topic (confirmation required)."
  type        = list(string)
  default     = []
}

variable "alert_https_endpoints" {
  description = "HTTPS endpoints subscribed to the topic (Datadog AWS SNS integration URL, PagerDuty...)."
  type        = list(string)
  default     = []
  # Not marked sensitive: Terraform forbids sensitive values as for_each keys.
  # Store the value as a sensitive HCP Terraform variable instead.
}

variable "crl_urls" {
  description = "CRL URLs to watch, keyed by a STABLE name (e.g. CA name). A map (not a list) because URLs contain CA IDs unknown until apply, and for_each keys must be known at plan time."
  type        = map(string)
  default     = {}
}

variable "crl_min_hours_remaining" {
  description = "Alarm when a CRL's nextUpdate is closer than this many hours. Rule of thumb: 25% of the CRL validity."
  type        = number
  default     = 42 # 25% of a 7-day CRL
}

variable "crl_checker_source_dir" {
  description = "Path to lambda/crl_freshness_checker (stdlib only, no build needed)."
  type        = string
}

variable "log_retention_days" {
  description = "Retention of PKI event logs (PCI DSS 10.5.1 requires 12 months)."
  type        = number
  default     = 365
}

variable "tags" {
  description = "Tags."
  type        = map(string)
  default     = {}
}
