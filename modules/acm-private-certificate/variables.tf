variable "domain_name" {
  description = "Primary DNS name (CN), e.g. payments-api.internal.example.com."
  type        = string
}

variable "subject_alternative_names" {
  description = "Additional DNS names (SAN)."
  type        = list(string)
  default     = []
}

variable "certificate_authority_arn" {
  description = "ARN of the issuing AWS Private CA (owned or shared through RAM). Must be GENERAL_PURPOSE."
  type        = string

  validation {
    condition     = can(regex("^arn:aws[a-z-]*:acm-pca:[a-z0-9-]+:[0-9]{12}:certificate-authority/", var.certificate_authority_arn))
    error_message = "certificate_authority_arn must be an AWS Private CA ARN."
  }
}

variable "key_algorithm" {
  description = "Key algorithm of the certificate key pair (generated and kept by ACM)."
  type        = string
  default     = "EC_prime256v1"

  validation {
    condition     = contains(["RSA_2048", "RSA_3072", "RSA_4096", "EC_prime256v1", "EC_secp384r1"], var.key_algorithm)
    error_message = "key_algorithm must be RSA_2048|RSA_3072|RSA_4096|EC_prime256v1|EC_secp384r1."
  }
}

variable "allowed_domain_suffixes" {
  description = "DNS suffixes this team is allowed to request (mirrors the CA name constraints)."
  type        = list(string)
}

variable "allow_wildcard" {
  description = "Allow *.domain names (needs a PKI exception)."
  type        = bool
  default     = false
}

variable "owner" {
  description = "Owning team or distribution list (receives expiry alerts). Mandatory."
  type        = string

  validation {
    condition     = length(trimspace(var.owner)) > 0
    error_message = "owner is mandatory."
  }
}

variable "application" {
  description = "Application identifier (CMDB ID)."
  type        = string
}

variable "distribution" {
  description = <<-EOT
    Optional redistribution of the certificate to non-integrated workloads
    (EC2, on-prem, containers) after each renewal, handled by module
    acm-renewal-distributor:
      method               = "secretsmanager"
      secret_name          = optional custom secret name
      reader_role_arn      = IAM role of the workload allowed to read the secret
      ssm_target_tag_value = optional: instances tagged pki:cert=<value> get an
                             SSM Run Command that reloads the certificate
  EOT
  type = object({
    method               = string
    secret_name          = optional(string)
    reader_role_arn      = string
    ssm_target_tag_value = optional(string)
  })
  default = null

  validation {
    condition     = var.distribution == null || try(var.distribution.method == "secretsmanager", false)
    error_message = "distribution.method must be \"secretsmanager\"."
  }
}

variable "expiry_alarm" {
  description = "CloudWatch alarm on AWS/CertificateManager DaysToExpiry."
  type = object({
    enabled        = optional(bool, true)
    threshold_days = optional(number, 30)
    sns_topic_arns = optional(list(string), [])
  })
  default = {}
}

variable "tags" {
  description = "Additional tags."
  type        = map(string)
  default     = {}
}
