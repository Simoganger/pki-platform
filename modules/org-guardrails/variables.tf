variable "policy_name" {
  description = "SCP name."
  type        = string
  default     = "pki-guardrails"
}

variable "pki_account_ids" {
  description = "Accounts allowed to create AWS Private CAs."
  type        = list(string)
}

variable "privileged_role_arn_patterns" {
  description = "Role ARN patterns allowed to perform trust-changing CA operations (HCP Terraform apply role, break-glass)."
  type        = list(string)
  # e.g. ["arn:aws:iam::*:role/hcp-terraform-pki-apply*", "arn:aws:iam::*:role/pki-break-glass"]
}

variable "target_ids" {
  description = "Root, OU or account IDs the SCP is attached to."
  type        = list(string)
}

variable "tags" {
  description = "Tags."
  type        = map(string)
  default     = {}
}
