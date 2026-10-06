###############################################################################
# Workspace: pki-org-guardrails   (AWS Organizations management / delegated admin)
#
# Applies the PKI Service Control Policy. Changes here are reviewed by both the
# PKI team and the cloud platform team (CODEOWNERS).
###############################################################################

terraform {
  required_version = ">= 1.9.0"

  cloud {
    workspaces {
      name = "pki-org-guardrails"
    }
  }

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.14"
    }
  }
}

provider "aws" {
  region = "ca-central-1"
}

variable "pki_account_ids" {
  description = "PKI accounts (nonprod, prod)."
  type        = list(string)
}

variable "target_ids" {
  description = "OUs / root where the SCP is attached. Start with a sandbox OU."
  type        = list(string)
}

module "pki_scp" {
  source = "../../../modules/org-guardrails"

  pki_account_ids = var.pki_account_ids
  privileged_role_arn_patterns = [
    "arn:aws:iam::*:role/hcp-terraform-pki-apply*",
    "arn:aws:iam::*:role/pki-break-glass",
  ]
  target_ids = var.target_ids
}
