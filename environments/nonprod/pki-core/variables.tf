variable "region" {
  description = "Primary AWS region of the PKI."
  type        = string
  default     = "ca-central-1"
}

variable "environment" {
  description = "Environment name."
  type        = string
  default     = "nonprod"
}

variable "organization_name" {
  description = "Organization name used in CA subjects."
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
  description = "Stable public hostname of the CDP (e.g. crl.pki-nonprod.example.com). null = use the CloudFront domain name."
  type        = string
  default     = null
}

variable "public_route53_zone_id" {
  description = "Public hosted zone for crl_hostname."
  type        = string
  default     = null
}

variable "issuing_cas" {
  description = "Issuing CAs to create, keyed by short name."
  type = map(object({
    usage                       = string
    usage_mode                  = optional(string, "GENERAL_PURPOSE")
    common_name                 = string
    key_algorithm               = optional(string, "EC_prime256v1")
    signing_algorithm           = optional(string, "SHA256WITHECDSA")
    validity_years              = optional(number, 5)
    crl_expiration_days         = optional(number, 7)
    ocsp_enabled                = optional(bool, false)
    name_constraints_der_base64 = optional(string)
    share_with                  = optional(list(string), [])
  }))
}

variable "alert_emails" {
  description = "E-mails subscribed to PKI alerts."
  type        = list(string)
  default     = []
}

variable "alert_https_endpoints" {
  description = "HTTPS endpoints (Datadog / PagerDuty) subscribed to PKI alerts."
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
