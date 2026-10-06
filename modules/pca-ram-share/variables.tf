variable "name" {
  description = "Name of the RAM resource share."
  type        = string
}

variable "certificate_authority_arns" {
  description = "Issuing CA ARNs to share. Never share a root CA."
  type        = list(string)
}

variable "principals" {
  description = "Organization OU ARNs (arn:aws:organizations::<mgmt>:ou/o-xxx/ou-xxx) or 12-digit account IDs."
  type        = list(string)

  validation {
    condition = alltrue([
      for p in var.principals : can(regex("^[0-9]{12}$", p)) || can(regex("^arn:aws[a-z-]*:organizations::[0-9]{12}:(ou|organization)/", p))
    ])
    error_message = "Each principal must be an account ID or an AWS Organizations OU / organization ARN."
  }
}

variable "permission_arns" {
  description = "RAM managed permission ARNs. Empty = AWSRAMDefaultPermissionCertificateAuthority."
  type        = list(string)
  default     = []
}

variable "tags" {
  description = "Tags."
  type        = map(string)
  default     = {}
}
