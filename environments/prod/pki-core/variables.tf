variable "region" {
  description = "Primary AWS region."
  type        = string
  default     = "ca-central-1"
}

variable "environment" {
  description = "Environment name."
  type        = string
  default     = "prod"
}

variable "organization_name" {
  description = "Organization name in CA subjects."
  type        = string
  default     = "Example Bank"
}

variable "owner_email" {
  description = "PKI team distribution list."
  type        = string
}

variable "cost_center" {
  description = "Cost center tag."
  type        = string
  default     = "data-protection"
}

variable "crl_hostname" {
  description = "Stable CDP hostname, e.g. crl.pki.example.com. Embedded in every certificate: never change it."
  type        = string
}

variable "ocsp_hostname" {
  description = "Optional OCSP hostname, e.g. ocsp.pki.example.com."
  type        = string
  default     = null
}

variable "public_route53_zone_id" {
  description = "Public hosted zone of crl_hostname / ocsp_hostname."
  type        = string
}

variable "access_log_bucket" {
  description = "Bucket for CloudFront / S3 access logs."
  type        = string
  default     = null
}

variable "offline_root_crl_url" {
  description = "URL of the CRL published by the offline root (watched by the CRL checker)."
  type        = string
  default     = null
}

variable "issuing_cas" {
  description = "Issuing CAs signed by the offline root."
  type = map(object({
    usage               = string
    usage_mode          = optional(string, "GENERAL_PURPOSE")
    common_name         = string
    key_algorithm       = optional(string, "EC_prime256v1")
    signing_algorithm   = optional(string, "SHA256WITHECDSA")
    crl_expiration_days = optional(number, 7)
    ocsp_enabled        = optional(bool, true)
    share_with          = optional(list(string), [])
  }))
}

variable "alert_emails" {
  description = "E-mails subscribed to PKI alerts."
  type        = list(string)
  default     = []
}

variable "alert_https_endpoints" {
  description = "HTTPS endpoints subscribed to PKI alerts."
  type        = list(string)
  default     = []
}

variable "connector_ad" {
  description = "AWS Private CA Connector for Active Directory."
  type = object({
    enabled            = optional(bool, false)
    directory_id       = optional(string)
    issuing_ca_key     = optional(string, "windows-issuing-g1")
    security_group_ids = optional(list(string), [])

    # Template security: AD group allowed to enroll / auto-enroll (e.g. "Domain Computers")
    enroll_group_name = optional(string, "Domain Computers")
    enroll_group_sid  = optional(string) # S-1-5-21-...-515

    # ADCS template names superseded by the new template (migration)
    superseded_adcs_templates = optional(list(string), [])
  })
  default = {}
}
