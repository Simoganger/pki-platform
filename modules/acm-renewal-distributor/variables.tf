variable "name_prefix" {
  description = "Prefix for resource names, e.g. \"pki-nonprod\"."
  type        = string
}

variable "lambda_source_dir" {
  description = "Directory containing the BUILT Lambda package (handler.py + vendored cryptography). Build with `make lambda-build`."
  type        = string
}

variable "secret_name_prefix" {
  description = "Prefix of the Secrets Manager secrets created for certificates."
  type        = string
  default     = "pki/certs/"
}

variable "notification_topic_arn" {
  description = "SNS topic notified after each redistribution (module pki-monitoring output)."
  type        = string
}

variable "log_retention_days" {
  description = "Lambda log retention (PCI DSS 10.5.1: 12 months)."
  type        = number
  default     = 365
}

variable "logs_kms_key_arn" {
  description = "Optional KMS key for the log group."
  type        = string
  default     = null
}

variable "tags" {
  description = "Tags."
  type        = map(string)
  default     = {}
}
