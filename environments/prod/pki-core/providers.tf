# Credentials: NONE in code. HCP Terraform obtains short-lived AWS credentials
# through OIDC "dynamic provider credentials" (workspace env vars
# TFC_AWS_PROVIDER_AUTH, TFC_AWS_PLAN_ROLE_ARN, TFC_AWS_APPLY_ROLE_ARN set by
# bootstrap/hcp-terraform). Plans run with a read-only role, applies with the
# apply role.

provider "aws" {
  region = var.region

  default_tags {
    tags = local.default_tags
  }
}

# CloudFront only accepts ACM certificates from us-east-1.
provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"

  default_tags {
    tags = local.default_tags
  }
}

# AWS Cloud Control provider: needed for AWS Private CA Connector for AD.
# Uses the same HCP Terraform AWS dynamic credentials as the aws provider
# (TFC_AWS_* variables); confirm awscc support on your TFE version if self-hosted.
provider "awscc" {
  region = var.region
}
