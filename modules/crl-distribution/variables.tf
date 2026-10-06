variable "bucket_name" {
  description = "Globally unique name of the CRL bucket."
  type        = string
}

variable "aliases" {
  description = "Stable DNS names for the CDP, e.g. [\"crl.pki.example.com\"]. Must match the custom_cname of the CAs."
  type        = list(string)
  default     = []
}

variable "alias_acm_certificate_arn_us_east_1" {
  description = "ACM certificate (us-east-1) covering the aliases. Required by CloudFront when aliases are set."
  type        = string
  default     = null
}

variable "route53_zone_id" {
  description = "Hosted zone in which to create alias records for the CDP names (optional)."
  type        = string
  default     = null
}

variable "cache_ttl_seconds" {
  description = "CloudFront TTL for CRLs. Keep it well below the CRL publication interval."
  type        = number
  default     = 300
}

variable "price_class" {
  description = "CloudFront price class."
  type        = string
  default     = "PriceClass_100"
}

variable "noncurrent_crl_retention_days" {
  description = "How long previous CRL versions are kept."
  type        = number
  default     = 400
}

variable "access_log_bucket" {
  description = "Optional bucket name for S3 / CloudFront access logs."
  type        = string
  default     = null
}

variable "tags" {
  description = "Tags."
  type        = map(string)
  default     = {}
}
