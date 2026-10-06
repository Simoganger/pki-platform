###############################################################################
# Workspace: workload-payments-nonprod   (AWS account: a WORKLOAD account)
#
# What an application team adds to its own Terraform to consume the PKI
# "vending machine". The issuing CA lives in the PKI account and is shared to
# this account's OU through AWS RAM.
#
#   1. payments-api   -> private cert on an ALB      (ACM renews + deploys, zero touch)
#   2. payments-batch -> private cert exported to EC2 (ACM renews, distributor
#                        pushes it to Secrets Manager, SSM reloads nginx)
#   3. monitoring of ACM events in THIS account (ACM events are regional and
#      per account, so each consuming account runs its own rules)
###############################################################################

terraform {
  required_version = ">= 1.9.0"

  cloud {
    workspaces {
      name = "workload-payments-nonprod"
    }
  }

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.14"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.7"
    }
    tfe = {
      source  = "hashicorp/tfe"
      version = "~> 0.68"
    }
  }
}

provider "aws" {
  region = "ca-central-1"
  default_tags {
    tags = {
      environment = "nonprod"
      application = "payments"
      managed_by  = "terraform"
    }
  }
}

provider "tfe" {}

variable "hcp_organization" {
  description = "HCP Terraform organization."
  type        = string
}

variable "payments_batch_instance_role_arn" {
  description = "IAM role of the EC2 instances running the batch service (allowed to read the certificate secret)."
  type        = string
}

data "tfe_outputs" "pki_core" {
  organization = var.hcp_organization
  workspace    = "pki-core-nonprod"
}

locals {
  servers_ca_arn = data.tfe_outputs.pki_core.nonsensitive_values.issuing_ca_arns["servers-issuing-g1"]
  repo_root      = "${path.root}/../../.."
}

module "monitoring" {
  source = "../../../modules/pki-monitoring"

  name_prefix            = "pki-payments-nonprod"
  alert_emails           = ["team-payments@example.com"]
  crl_checker_source_dir = "${local.repo_root}/lambda/crl_freshness_checker"
  crl_urls               = {} # CRLs are watched centrally by the PKI account
}

# 1. ALB certificate: nothing else to do, ACM renews and redeploys it.
module "cert_payments_api" {
  source = "../../../modules/acm-private-certificate"

  domain_name               = "payments-api.nonprod.internal.example.com"
  subject_alternative_names = ["payments.nonprod.internal.example.com"]
  certificate_authority_arn = local.servers_ca_arn
  allowed_domain_suffixes   = [".nonprod.internal.example.com"]
  owner                     = "team-payments@example.com"
  application               = "APP-1234"

  expiry_alarm = {
    sns_topic_arns = [module.monitoring.alerts_topic_arn]
  }
}

# 2. EC2 certificate, redistributed after every renewal.
module "cert_payments_batch" {
  source = "../../../modules/acm-private-certificate"

  domain_name               = "payments-batch.nonprod.internal.example.com"
  certificate_authority_arn = local.servers_ca_arn
  allowed_domain_suffixes   = [".nonprod.internal.example.com"]
  owner                     = "team-payments@example.com"
  application               = "APP-1234"

  distribution = {
    method               = "secretsmanager"
    reader_role_arn      = var.payments_batch_instance_role_arn
    ssm_target_tag_value = "payments-batch"
  }

  expiry_alarm = {
    sns_topic_arns = [module.monitoring.alerts_topic_arn]
  }
}

module "renewal_distributor" {
  source = "../../../modules/acm-renewal-distributor"

  name_prefix            = "pki-payments-nonprod"
  lambda_source_dir      = "${local.repo_root}/lambda/dist/acm_renewal_distributor"
  notification_topic_arn = module.monitoring.alerts_topic_arn
}

output "payments_api_certificate_arn" {
  description = "Attach to the ALB HTTPS listener."
  value       = module.cert_payments_api.arn
}

output "payments_batch_secret_name" {
  description = "Secret read by /usr/local/bin/pki-cert-sync.sh on the batch hosts."
  value       = module.cert_payments_batch.secret_name
}

output "first_distribution_command" {
  description = "ACM only emits 'Certificate Available' on issuance/renewal; run this once after the first apply to push the initial certificate."
  value       = "aws lambda invoke --function-name ${module.renewal_distributor.lambda_function_name} --cli-binary-format raw-in-base64-out --payload '{\"certificateArn\":\"${module.cert_payments_batch.arn}\"}' /dev/stdout"
}
