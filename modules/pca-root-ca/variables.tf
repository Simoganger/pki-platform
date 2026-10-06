variable "name" {
  description = "Short logical name of the CA (used in tags), e.g. \"bnc-lab-root-g1\"."
  type        = string
}

variable "subject" {
  description = "X.509 subject of the root CA certificate."
  type = object({
    common_name         = string
    organization        = string
    organizational_unit = optional(string)
    country             = optional(string, "CA")
    state               = optional(string)
    locality            = optional(string)
  })
}

variable "key_algorithm" {
  description = "Key algorithm of the root CA. RSA_4096 maximizes compatibility for a long-lived root; EC_secp384r1 is a strong modern choice."
  type        = string
  default     = "RSA_4096"

  validation {
    condition     = contains(["RSA_2048", "RSA_3072", "RSA_4096", "EC_prime256v1", "EC_secp384r1", "EC_secp521r1", "ML_DSA_44", "ML_DSA_65", "ML_DSA_87"], var.key_algorithm)
    error_message = "Unsupported key_algorithm."
  }

  validation {
    condition     = var.key_algorithm != "RSA_2048"
    error_message = "RSA_2048 is not allowed for a root CA (internal crypto standard: >= RSA_3072 or ECC P-384)."
  }
}

variable "signing_algorithm" {
  description = "Signature algorithm used by the root (must match the key family: SHA*WITHRSA for RSA, SHA*WITHECDSA for EC, ML_DSA_* for ML-DSA)."
  type        = string
  default     = "SHA512WITHRSA"
}

variable "key_storage_security_standard" {
  description = "FIPS level of the AWS-managed HSM that stores the CA key."
  type        = string
  default     = "FIPS_140_2_LEVEL_3_OR_HIGHER"
}

variable "validity_years" {
  description = "Validity of the self-signed root certificate, in years."
  type        = number
  default     = 10

  validation {
    condition     = var.validity_years >= 5 && var.validity_years <= 25
    error_message = "Root validity must be between 5 and 25 years."
  }
}

variable "crl" {
  description = "CRL publication settings. The bucket must allow acm-pca.amazonaws.com to write (module crl-distribution does this)."
  type = object({
    enabled            = optional(bool, true)
    expiration_in_days = optional(number, 365) # root CRLs are long: the root signs rarely
    s3_bucket_name     = optional(string)
    custom_cname       = optional(string) # e.g. crl.pki.example.com (no scheme)
  })
  default = {}

  validation {
    condition     = !var.crl.enabled || var.crl.s3_bucket_name != null
    error_message = "crl.s3_bucket_name is required when crl.enabled = true."
  }
}

variable "permanent_deletion_time_in_days" {
  description = "Restore window (7-30 days) after a delete request."
  type        = number
  default     = 30

  validation {
    condition     = var.permanent_deletion_time_in_days >= 7 && var.permanent_deletion_time_in_days <= 30
    error_message = "Must be between 7 and 30."
  }
}

variable "tags" {
  description = "Tags applied to every resource (owner, data_classification, cost center...)."
  type        = map(string)
  default     = {}
}
