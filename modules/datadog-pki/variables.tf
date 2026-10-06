variable "env" {
  description = "Environment tag value (nonprod, prod)."
  type        = string
}

variable "notify_handles" {
  description = "Datadog notification handles, e.g. [\"@pagerduty-pki\", \"@slack-pki-alerts\", \"@pki-team@example.com\"]."
  type        = list(string)
}

variable "security_notify_handles" {
  description = "Extra handles for security monitors (SOC)."
  type        = list(string)
  default     = []
}

variable "runbook_base_url" {
  description = "Base URL of the runbooks (docs/runbooks in this repository)."
  type        = string
}

variable "metric_acm_days_to_expiry" {
  description = "Datadog metric for ACM DaysToExpiry."
  type        = string
  default     = "aws.certificatemanager.days_to_expiry"
}

variable "metric_crl_hours_until_next_update" {
  description = "Datadog metric for the PKI/CRL HoursUntilNextUpdate custom CloudWatch metric (check the exact name Datadog assigns to custom namespaces)."
  type        = string
  default     = "aws.pki.crl.hours_until_next_update"
}

variable "cert_warning_days" {
  description = "Warning threshold in days."
  type        = number
  default     = 30
}

variable "cert_critical_days" {
  description = "Critical threshold in days."
  type        = number
  default     = 14
}

variable "crl_warning_hours" {
  description = "CRL warning threshold (hours before nextUpdate)."
  type        = number
  default     = 72
}

variable "crl_critical_hours" {
  description = "CRL critical threshold (hours before nextUpdate)."
  type        = number
  default     = 42
}

variable "crl_urls" {
  description = "CRL URLs checked by HTTP synthetics, keyed by CA name."
  type        = map(string)
  default     = {}
}

variable "tls_endpoints" {
  description = "TLS endpoints checked by SSL synthetics. Use private location IDs for internal endpoints."
  type = list(object({
    host      = string
    port      = optional(number, 443)
    locations = optional(list(string), [])
  }))
  default = []
}

variable "synthetics_locations" {
  description = "Default synthetics locations, e.g. [\"aws:ca-central-1\"] or [\"pl:bnc-private-location-xxxx\"]."
  type        = list(string)
  default     = ["aws:ca-central-1"]
}

variable "hsm_monitoring_enabled" {
  description = "Create the HSM SNMP monitor."
  type        = bool
  default     = true
}

variable "hsm_device_namespace" {
  description = "Datadog device_namespace configured on the SNMP instances of the HSMs."
  type        = string
  default     = "hsm"
}
