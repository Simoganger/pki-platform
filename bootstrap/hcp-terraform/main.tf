###############################################################################
# Bootstrap: HCP Terraform organization objects for the PKI platform.
# Run once by an HCP Terraform organization owner (TFE_TOKEN = user token).
#
# Creates:
#   - project "pki-platform"
#   - one API-driven workspace per root module (GitHub Actions uploads the
#     configuration; no VCS connection, so runs are only triggered by the
#     reviewed pipeline)
#   - AWS dynamic provider credentials per workspace (plan role / apply role)
#   - teams: pki-engineers (write), pki-ci-plan (plan only), pki-ci-apply (apply)
#   - Sentinel policy set enforced on every PKI workspace
#   - variable set with the Datadog API/APP keys (sensitive) for observability
###############################################################################

terraform {
  required_version = ">= 1.9.0"

  required_providers {
    tfe = {
      source  = "hashicorp/tfe"
      version = "~> 0.68"
    }
  }
}

provider "tfe" {
  hostname     = var.hcp_hostname
  organization = var.hcp_organization
}

###############################################################################
# Project + workspaces
###############################################################################
resource "tfe_project" "pki" {
  name        = var.project_name
  description = "PKI platform - AWS Private CA, ACM, observability (Data Protection team)"
}

resource "tfe_workspace" "this" {
  for_each = var.workspaces

  name              = each.key
  project_id        = tfe_project.pki.id
  description       = each.value.description
  working_directory = each.value.working_directory
  terraform_version = var.terraform_version
  auto_apply        = false # every apply is confirmed by the GitHub "production" environment approval
  queue_all_runs    = false

  # Drift detection + continuous validation ("health assessments"):
  # detects manual console changes to CAs, buckets, policies.
  assessments_enabled = true

  tag_names = concat(["pki", each.value.environment], each.value.pci ? ["pci"] : [])
}

# Remote state sharing: only the workspaces listed in share_state_with can read
# this workspace's outputs (tfe_outputs). Never enable global remote state.
resource "tfe_workspace_settings" "this" {
  for_each = var.workspaces

  workspace_id              = tfe_workspace.this[each.key].id
  execution_mode            = "remote"
  global_remote_state       = false
  remote_state_consumer_ids = [for c in each.value.share_state_with : tfe_workspace.this[c].id]
}

###############################################################################
# AWS dynamic provider credentials (OIDC) - no AWS keys in HCP Terraform
###############################################################################
resource "tfe_variable" "aws_provider_auth" {
  for_each = var.workspaces

  workspace_id = tfe_workspace.this[each.key].id
  category     = "env"
  key          = "TFC_AWS_PROVIDER_AUTH"
  value        = "true"
  description  = "Enable AWS dynamic provider credentials"
}

resource "tfe_variable" "aws_plan_role" {
  for_each = var.workspaces

  workspace_id = tfe_workspace.this[each.key].id
  category     = "env"
  key          = "TFC_AWS_PLAN_ROLE_ARN"
  value        = var.aws_roles[each.value.aws_account].plan_role_arn
  description  = "Read-only role assumed during plan"
}

resource "tfe_variable" "aws_apply_role" {
  for_each = var.workspaces

  workspace_id = tfe_workspace.this[each.key].id
  category     = "env"
  key          = "TFC_AWS_APPLY_ROLE_ARN"
  value        = var.aws_roles[each.value.aws_account].apply_role_arn
  description  = "Scoped write role assumed during apply"
}

resource "tfe_variable" "hcp_organization" {
  for_each = { for k, v in var.workspaces : k => v if v.needs_hcp_org_var }

  workspace_id = tfe_workspace.this[each.key].id
  category     = "terraform"
  key          = "hcp_organization"
  value        = var.hcp_organization
}

###############################################################################
# Teams
###############################################################################
resource "tfe_team" "engineers" {
  name       = "pki-engineers"
  visibility = "organization"
}

resource "tfe_team" "ci_plan" {
  name       = "pki-ci-plan"
  visibility = "secret"
}

resource "tfe_team" "ci_apply" {
  name       = "pki-ci-apply"
  visibility = "secret"
}

resource "tfe_team_project_access" "engineers" {
  team_id    = tfe_team.engineers.id
  project_id = tfe_project.pki.id
  access     = "write" # humans can queue plans and read state, applies go through CI
}

resource "tfe_team_project_access" "ci_plan" {
  team_id    = tfe_team.ci_plan.id
  project_id = tfe_project.pki.id
  access     = "custom"

  project_access {
    settings = "read"
    teams    = "none"
  }

  workspace_access {
    runs           = "plan"
    variables      = "read"
    state_versions = "read-outputs"
    sentinel_mocks = "none"
    create         = false
    locking        = false
    delete         = false
    move           = false
    run_tasks      = false
  }
}

resource "tfe_team_project_access" "ci_apply" {
  team_id    = tfe_team.ci_apply.id
  project_id = tfe_project.pki.id
  access     = "custom"

  project_access {
    settings = "read"
    teams    = "none"
  }

  workspace_access {
    runs           = "apply"
    variables      = "read"
    state_versions = "read-outputs"
    sentinel_mocks = "none"
    create         = false
    locking        = false
    delete         = false
    move           = false
    run_tasks      = false
  }
}

# Team tokens are created MANUALLY (Settings > Teams > Team API token) and
# stored as GitHub environment secrets, so they never land in this state:
#   pki-ci-plan  -> repository secret      TF_API_TOKEN_PLAN
#   pki-ci-apply -> environment secrets    TF_API_TOKEN (environments nonprod / production)
# Set an expiry on team tokens and rotate them (docs/runbooks/secret-rotation.md).

###############################################################################
# Sentinel policy set
###############################################################################
data "tfe_slug" "sentinel" {
  source_path = "${path.module}/../../policies/sentinel"
}

resource "tfe_policy_set" "pki" {
  name          = "pki-guardrails"
  description   = "Mandatory PKI policies (key algorithms, tags, CA protection, sharing)"
  kind          = "sentinel"
  agent_enabled = true
  workspace_ids = [for ws in tfe_workspace.this : ws.id]
  slug          = data.tfe_slug.sentinel

  policy_tool_version = var.sentinel_version
}

###############################################################################
# Datadog credentials for observability workspaces
###############################################################################
resource "tfe_variable_set" "datadog" {
  name        = "datadog-pki"
  description = "Datadog API / APP keys for PKI observability workspaces"
}

resource "tfe_variable" "dd_api_key" {
  variable_set_id = tfe_variable_set.datadog.id
  category        = "env"
  key             = "DD_API_KEY"
  value           = var.datadog_api_key
  sensitive       = true
}

resource "tfe_variable" "dd_app_key" {
  variable_set_id = tfe_variable_set.datadog.id
  category        = "env"
  key             = "DD_APP_KEY"
  value           = var.datadog_app_key
  sensitive       = true
}

resource "tfe_workspace_variable_set" "datadog" {
  for_each = { for k, v in var.workspaces : k => v if v.needs_datadog }

  variable_set_id = tfe_variable_set.datadog.id
  workspace_id    = tfe_workspace.this[each.key].id
}
