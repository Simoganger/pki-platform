variable "name" {
  description = "Logical CA name, e.g. \"servers-issuing-g1\"."
  type        = string
}

variable "usage" {
  description = "What this CA is for (tag pki:usage). Keep one CA per usage / risk zone."
  type        = string

  validation {
    condition     = contains(["tls-server", "tls-client", "mtls-workload", "windows-autoenroll", "code-signing", "device", "pci"], var.usage)
    error_message = "usage must be one of: tls-server, tls-client, mtls-workload, windows-autoenroll, code-signing, device, pci."
  }
}

variable "subject" {
  description = "X.509 subject of the issuing CA."
  type = object({
    common_name         = string
    organization        = string
    organizational_unit = optional(string)
    country             = optional(string, "CA")
    state               = optional(string)
    locality            = optional(string)
  })
}

variable "usage_mode" {
  description = "GENERAL_PURPOSE (any validity) or SHORT_LIVED_CERTIFICATE (max 7 days, much cheaper per certificate, revocation rarely needed)."
  type        = string
  default     = "GENERAL_PURPOSE"

  validation {
    condition     = contains(["GENERAL_PURPOSE", "SHORT_LIVED_CERTIFICATE"], var.usage_mode)
    error_message = "usage_mode must be GENERAL_PURPOSE or SHORT_LIVED_CERTIFICATE."
  }
}

variable "key_algorithm" {
  description = "Key algorithm of the issuing CA."
  type        = string
  default     = "EC_prime256v1"

  validation {
    condition     = contains(["RSA_2048", "RSA_3072", "RSA_4096", "EC_prime256v1", "EC_secp384r1", "EC_secp521r1", "ML_DSA_44", "ML_DSA_65", "ML_DSA_87"], var.key_algorithm)
    error_message = "Unsupported key_algorithm."
  }
}

variable "signing_algorithm" {
  description = "Algorithm THIS CA uses to sign end-entity certs and CRLs (must match key_algorithm family)."
  type        = string
  default     = "SHA256WITHECDSA"
}

variable "key_storage_security_standard" {
  description = "FIPS level of the AWS-managed HSM that stores the CA key."
  type        = string
  default     = "FIPS_140_2_LEVEL_3_OR_HIGHER"
}

variable "signing_mode" {
  description = "PCA = signed by an AWS Private CA parent. EXTERNAL = signed offline by an on-prem HSM root (two-phase apply)."
  type        = string
  default     = "PCA"

  validation {
    condition     = contains(["PCA", "EXTERNAL"], var.signing_mode)
    error_message = "signing_mode must be PCA or EXTERNAL."
  }
}

variable "parent_ca_arn" {
  description = "ARN of the parent AWS Private CA (signing_mode = PCA)."
  type        = string
  default     = null
}

variable "parent_signing_algorithm" {
  description = "Signing algorithm of the PARENT (matches the parent's key), e.g. SHA512WITHRSA for an RSA root."
  type        = string
  default     = null
}

variable "validity_years" {
  description = "Validity of the issuing CA certificate (signing_mode = PCA). Must end before the parent's own expiry."
  type        = number
  default     = 5

  validation {
    condition     = var.validity_years >= 1 && var.validity_years <= 10
    error_message = "Issuing CA validity must be between 1 and 10 years."
  }
}

variable "external_signed_certificate" {
  description = "Phase 2 of signing_mode = EXTERNAL: the PEM certificate signed by the offline root, and its chain (root PEM, plus intermediates if any)."
  type = object({
    certificate_pem       = string
    certificate_chain_pem = string
  })
  default = null
}

variable "name_constraints_der_base64" {
  description = "Optional base64 DER value of a NameConstraints extension (scripts/build_name_constraints.py). Restricts the DNS names this CA can sign."
  type        = string
  default     = null
}

variable "crl" {
  description = "CRL settings. Issuing CAs use short CRLs (default 7 days) so revocations propagate quickly."
  type = object({
    enabled            = optional(bool, true)
    expiration_in_days = optional(number, 7)
    s3_bucket_name     = optional(string)
    custom_cname       = optional(string)
  })
  default = {}

  validation {
    condition     = !var.crl.enabled || var.crl.s3_bucket_name != null
    error_message = "crl.s3_bucket_name is required when crl.enabled = true."
  }
}

variable "ocsp" {
  description = "AWS-managed OCSP responder. custom_cname requires a DNS CNAME to the regional ocsp.acm-pca endpoint."
  type = object({
    enabled      = optional(bool, false)
    custom_cname = optional(string)
  })
  default = {}
}

variable "allow_acm_managed_renewal" {
  description = "Grant acm.amazonaws.com the permissions needed to issue and auto-renew ACM private certificates."
  type        = bool
  default     = true
}

variable "resource_policy_json" {
  description = "Optional resource-based policy for the CA (cross-account issuance through RAM)."
  type        = string
  default     = null
}

variable "enabled" {
  description = "Set to false to DISABLE issuance (e.g. during an incident) without deleting the CA."
  type        = bool
  default     = true
}

variable "permanent_deletion_time_in_days" {
  description = "Restore window (7-30 days) after a delete request."
  type        = number
  default     = 30
}

variable "tags" {
  description = "Tags applied to the CA."
  type        = map(string)
  default     = {}
}
