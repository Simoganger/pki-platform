###############################################################################
# Workspace: pki-observability-nonprod
#
# Separate workspace (and state) from pki-core on purpose:
#   - observability changes (a new monitor) never put the CAs at risk;
#   - the Datadog / Splunk credentials are only present in this workspace.
#
# Reads pki-core outputs through HCP Terraform (tfe_outputs), never by
# duplicating ARNs by hand.
###############################################################################

terraform {
  required_version = ">= 1.9.0"

  cloud {
    workspaces {
      name = "pki-observability-nonprod"
    }
  }

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.14"
    }
    datadog = {
      source  = "DataDog/datadog"
      version = "~> 4.27"
    }
    tfe = {
      source  = "hashicorp/tfe"
      version = "~> 0.68"
    }
  }
}

provider "aws" {
  region = var.region
  default_tags {
    tags = {
      environment = var.environment
      owner       = var.owner_email
      managed_by  = "terraform"
      repository  = "pki-platform"
    }
  }
}

# Credentials from sensitive workspace environment variables DD_API_KEY and
# DD_APP_KEY (variable set "datadog-pki", created by bootstrap/hcp-terraform).
provider "datadog" {
  api_url = var.datadog_api_url
}

# Uses the workspace's own HCP Terraform run token to read other workspaces'
# outputs (remote state sharing must allow it - bootstrap/hcp-terraform).
provider "tfe" {}

data "tfe_outputs" "pki_core" {
  organization = var.hcp_organization
  workspace    = "pki-core-${var.environment}"
}

locals {
  name_prefix = "pki-${var.environment}"
  core        = data.tfe_outputs.pki_core.nonsensitive_values
}

data "aws_caller_identity" "current" {}

###############################################################################
# CloudTrail + tripwires + Splunk SQS feed
###############################################################################
module "audit_logging" {
  source = "../../../modules/pki-audit-logging"

  trail_name          = "${local.name_prefix}-audit"
  bucket_name         = "${local.name_prefix}-audit-${data.aws_caller_identity.current.account_id}"
  alerts_topic_arn    = local.core.alerts_topic_arn
  log_admin_role_arns = var.log_admin_role_arns
  object_lock = {
    enabled = true
    mode    = var.environment == "prod" ? "COMPLIANCE" : "GOVERNANCE"
    days    = 365
  }

  trusted_automation_role_name_patterns = ["hcp-terraform-pki-apply*"]

  splunk = {
    enabled              = var.splunk.enabled
    reader_principal_arn = var.splunk.reader_principal_arn
    external_id          = var.splunk.external_id
  }
}

###############################################################################
# Near-real-time PKI events to Splunk HEC
###############################################################################
module "splunk_firehose" {
  source = "../../../modules/splunk-firehose"
  count  = var.splunk.enabled && var.splunk.hec_endpoint != null ? 1 : 0

  name_prefix          = local.name_prefix
  hec_endpoint         = var.splunk.hec_endpoint
  hec_token_secret_arn = var.splunk.hec_token_secret_arn
  backup_bucket_name   = "${local.name_prefix}-splunk-backup-${data.aws_caller_identity.current.account_id}"
  log_group_names      = concat(local.core.monitoring_log_group_names, [module.audit_logging.cloudwatch_log_group_name])
}

###############################################################################
# Datadog monitors, synthetics, dashboard
###############################################################################
module "datadog" {
  source = "../../../modules/datadog-pki"

  env                     = var.environment
  notify_handles          = var.datadog.notify_handles
  security_notify_handles = var.datadog.security_notify_handles
  runbook_base_url        = var.runbook_base_url
  crl_urls                = local.core.crl_urls
  tls_endpoints           = var.datadog.tls_endpoints
  synthetics_locations    = var.datadog.synthetics_locations
  hsm_monitoring_enabled  = var.datadog.hsm_monitoring_enabled
}
