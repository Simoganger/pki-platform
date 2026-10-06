variable "region" {
  description = "AWS region for the provider (IAM is global)."
  type        = string
  default     = "ca-central-1"
}

variable "environment" {
  description = "nonprod or prod (suffix of the role names)."
  type        = string
}

variable "hcp_organization" {
  description = "HCP Terraform organization name."
  type        = string
}

variable "hcp_project" {
  description = "HCP Terraform project holding the PKI workspaces."
  type        = string
  default     = "pki-platform"
}

variable "hcp_workspaces" {
  description = "Workspaces allowed to assume the roles in THIS account."
  type        = list(string)
  # nonprod: ["pki-core-nonprod", "pki-observability-nonprod"]
}

variable "github_repository" {
  description = "owner/repo allowed to run the inventory workflow (null = skip GitHub OIDC)."
  type        = string
  default     = null
}
