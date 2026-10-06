variable "domain_name" {
  description = "Public DNS name, e.g. crl.pki.example.com."
  type        = string
}

variable "subject_alternative_names" {
  description = "Additional public names."
  type        = list(string)
  default     = []
}

variable "route53_zone_id" {
  description = "Public hosted zone used for DNS validation."
  type        = string
}

variable "key_algorithm" {
  description = "RSA_2048 for maximum client compatibility, EC_prime256v1 for modern clients."
  type        = string
  default     = "RSA_2048"
}

variable "owner" {
  description = "Owning team."
  type        = string
}

variable "tags" {
  description = "Tags."
  type        = map(string)
  default     = {}
}
