variable "hcp_hostname" {
  description = "HCP Terraform hostname (app.terraform.io, or your Terraform Enterprise host)."
  type        = string
  default     = "app.terraform.io"
}

variable "hcp_organization" {
  description = "HCP Terraform organization."
  type        = string
}

variable "project_name" {
  description = "Project name (must match var.hcp_project of bootstrap/aws-oidc)."
  type        = string
  default     = "pki-platform"
}

variable "terraform_version" {
  description = "Terraform version pinned on the workspaces (keep aligned with .terraform-version and CI)."
  type        = string
  default     = "1.13.3"
}

variable "sentinel_version" {
  description = "Sentinel runtime version for the policy set."
  type        = string
  default     = "0.40.0"
}

variable "aws_roles" {
  description = "OIDC role ARNs per AWS account alias (outputs of bootstrap/aws-oidc)."
  type = map(object({
    plan_role_arn  = string
    apply_role_arn = string
  }))
}

variable "workspaces" {
  description = "Workspaces to create, keyed by workspace name."
  type = map(object({
    description       = string
    working_directory = string
    environment       = string
    aws_account       = string # key of var.aws_roles
    pci               = optional(bool, false)
    needs_datadog     = optional(bool, false)
    needs_hcp_org_var = optional(bool, false)
    share_state_with  = optional(list(string), [])
  }))

  default = {
    pki-core-nonprod = {
      description       = "Non-prod PKI hierarchy (PCA root + issuing CAs, CRL, RAM, monitoring)"
      working_directory = "environments/nonprod/pki-core"
      environment       = "nonprod"
      aws_account       = "pki-nonprod"
      share_state_with  = ["pki-observability-nonprod", "workload-payments-nonprod"]
    }
    pki-observability-nonprod = {
      description       = "Non-prod CloudTrail, Splunk, Datadog"
      working_directory = "environments/nonprod/observability"
      environment       = "nonprod"
      aws_account       = "pki-nonprod"
      needs_datadog     = true
      needs_hcp_org_var = true
    }
    workload-payments-nonprod = {
      description       = "Example consumer of the PKI vending machine"
      working_directory = "environments/nonprod/workload-payments-example"
      environment       = "nonprod"
      aws_account       = "payments-nonprod"
      needs_hcp_org_var = true
    }
    pki-core-prod = {
      description       = "Production issuing CAs signed by the offline root"
      working_directory = "environments/prod/pki-core"
      environment       = "prod"
      aws_account       = "pki-prod"
      pci               = true
      share_state_with  = ["pki-observability-prod"]
    }
    pki-observability-prod = {
      description       = "Production CloudTrail, Splunk, Datadog"
      working_directory = "environments/prod/observability"
      environment       = "prod"
      aws_account       = "pki-prod"
      pci               = true
      needs_datadog     = true
      needs_hcp_org_var = true
    }
  }
}

variable "datadog_api_key" {
  description = "Datadog API key (pass with TF_VAR_datadog_api_key, never in a file)."
  type        = string
  sensitive   = true
}

variable "datadog_app_key" {
  description = "Datadog application key scoped to monitors/synthetics/dashboards (TF_VAR_datadog_app_key)."
  type        = string
  sensitive   = true
}
