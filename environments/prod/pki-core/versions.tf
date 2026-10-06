terraform {
  required_version = ">= 1.9.0"

  # HCP Terraform (formerly Terraform Cloud). The organization comes from the
  # TF_CLOUD_ORGANIZATION environment variable (set in CI and locally), so the
  # same code works for any organization name.
  cloud {
    workspaces {
      name = "pki-core-prod"
    }
  }

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.14"
    }
    awscc = {
      source  = "hashicorp/awscc"
      version = "~> 1.58"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.7"
    }
  }
}
