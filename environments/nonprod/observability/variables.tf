variable "region" {
  description = "AWS region."
  type        = string
  default     = "ca-central-1"
}

variable "environment" {
  description = "Environment (must match the pki-core workspace suffix)."
  type        = string
  default     = "nonprod"
}

variable "hcp_organization" {
  description = "HCP Terraform organization name."
  type        = string
}

variable "owner_email" {
  description = "PKI team distribution list."
  type        = string
}

variable "runbook_base_url" {
  description = "Base URL of docs/runbooks in the Git server, used in alert messages."
  type        = string
  default     = "https://github.com/example-bank/pki-platform/blob/main/docs/runbooks"
}

variable "log_admin_role_arns" {
  description = "Break-glass roles allowed to delete audit objects."
  type        = list(string)
}

variable "datadog_api_url" {
  description = "Datadog API URL for your site (US1 https://api.datadoghq.com/, US3, US5, EU, AP1...)."
  type        = string
  default     = "https://api.datadoghq.com/"
}

variable "datadog" {
  description = "Datadog settings."
  type = object({
    notify_handles          = list(string)
    security_notify_handles = optional(list(string), [])
    synthetics_locations    = optional(list(string), ["aws:ca-central-1"])
    hsm_monitoring_enabled  = optional(bool, true)
    tls_endpoints = optional(list(object({
      host      = string
      port      = optional(number, 443)
      locations = optional(list(string), [])
    })), [])
  })
}

variable "splunk" {
  description = "Splunk integration settings."
  type = object({
    enabled              = optional(bool, false)
    reader_principal_arn = optional(string) # Splunk add-on IAM principal (SQS-based S3 input)
    external_id          = optional(string)
    hec_endpoint         = optional(string) # Firehose -> HEC
    hec_token_secret_arn = optional(string)
  })
  default = {}
}
