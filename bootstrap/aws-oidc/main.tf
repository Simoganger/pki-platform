###############################################################################
# Bootstrap: AWS identity federation (run ONCE per AWS account, by an admin,
# with local state or a dedicated HCP Terraform workspace).
#
# Creates:
#   - OIDC identity provider for HCP Terraform (app.terraform.io)
#   - hcp-terraform-pki-plan-<env>   : READ-ONLY, assumable only by PLAN phases
#   - hcp-terraform-pki-apply-<env>  : scoped write, assumable only by APPLY
#                                      phases of the listed workspaces
#   - OIDC identity provider for GitHub Actions
#   - github-pki-inventory-<env>     : read-only role for the scheduled
#                                      certificate inventory workflow
#
# NO long-lived access keys exist anywhere in this design.
###############################################################################

terraform {
  required_version = ">= 1.9.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.14"
    }
  }
}

provider "aws" {
  region = var.region
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
  hcp_host   = "app.terraform.io"

  # sub claim format: organization:<org>:project:<project>:workspace:<ws>:run_phase:<plan|apply>
  plan_subjects  = [for ws in var.hcp_workspaces : "organization:${var.hcp_organization}:project:${var.hcp_project}:workspace:${ws}:run_phase:plan"]
  apply_subjects = [for ws in var.hcp_workspaces : "organization:${var.hcp_organization}:project:${var.hcp_project}:workspace:${ws}:run_phase:apply"]
}

###############################################################################
# HCP Terraform OIDC provider
###############################################################################
resource "aws_iam_openid_connect_provider" "hcp_terraform" {
  url            = "https://${local.hcp_host}"
  client_id_list = ["aws.workload.identity"]
  # AWS validates the TLS chain of well-known OIDC providers itself; a
  # thumbprint is no longer required for new providers.
}

data "aws_iam_policy_document" "plan_trust" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.hcp_terraform.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "${local.hcp_host}:aud"
      values   = ["aws.workload.identity"]
    }
    # StringEquals (exact list), NOT StringLike with wildcards: a wildcard on
    # the workspace would let any workspace of the organization assume the role.
    condition {
      test     = "StringEquals"
      variable = "${local.hcp_host}:sub"
      values   = local.plan_subjects
    }
  }
}

data "aws_iam_policy_document" "apply_trust" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.hcp_terraform.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "${local.hcp_host}:aud"
      values   = ["aws.workload.identity"]
    }
    condition {
      test     = "StringEquals"
      variable = "${local.hcp_host}:sub"
      values   = local.apply_subjects
    }
  }
}

###############################################################################
# PLAN role: read-only
###############################################################################
resource "aws_iam_role" "plan" {
  name                 = "hcp-terraform-pki-plan-${var.environment}"
  description          = "HCP Terraform PLAN phase for PKI workspaces (read-only)"
  assume_role_policy   = data.aws_iam_policy_document.plan_trust.json
  max_session_duration = 3600
}

resource "aws_iam_role_policy_attachment" "plan_readonly" {
  role       = aws_iam_role.plan.name
  policy_arn = "arn:${local.partition}:iam::aws:policy/ReadOnlyAccess"
}

data "aws_iam_policy_document" "plan_deny" {
  statement {
    sid    = "NoSecretOrKeyMaterialDuringPlan"
    effect = "Deny"
    actions = [
      "secretsmanager:GetSecretValue",
      "acm:ExportCertificate",
      "acm-pca:IssueCertificate",
      "s3:GetObject",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "plan_deny" {
  name   = "deny-sensitive-reads"
  role   = aws_iam_role.plan.id
  policy = data.aws_iam_policy_document.plan_deny.json
}

###############################################################################
# APPLY role: scoped to what the PKI modules manage
###############################################################################
data "aws_iam_policy_document" "apply" {
  #checkov:skip=CKV_AWS_109:Terraform apply role must manage PKI resource policies; scoped by OIDC trust (apply phase of named workspaces), SCP, Sentinel and explicit denies
  #checkov:skip=CKV_AWS_110:IAM actions limited to roles named pki-*; see explicit deny statement
  #checkov:skip=CKV_AWS_111:Apply role is the deployment identity; blast radius limited to the PKI account
  #checkov:skip=CKV_AWS_356:Service-level permissions needed to create resources whose ARNs are unknown before creation
  statement {
    sid = "PKIServices"
    actions = [
      "acm-pca:*",
      "acm:*",
      "pca-connector-ad:*",
      "ds:DescribeDirectories",
      "ds:AuthorizeApplication",
      "ds:UnauthorizeApplication",
      "ds:UpdateAuthorizedApplication",
      "ram:*",
      "cloudfront:*",
      "route53:ChangeResourceRecordSets",
      "route53:GetChange",
      "route53:GetHostedZone",
      "route53:ListResourceRecordSets",
      "route53:ListHostedZones",
      "events:*",
      "sns:*",
      "sqs:*",
      "logs:*",
      "cloudwatch:*",
      "cloudtrail:*",
      "lambda:*",
      "ssm:*Document*",
      "ssm:AddTagsToResource",
      "ssm:RemoveTagsFromResource",
      "ssm:ListTagsForResource",
      "firehose:*",
      "kms:*",
      "tag:GetResources",
      "ec2:DescribeVpcs",
      "ec2:DescribeSubnets",
      "ec2:DescribeSecurityGroups",
    ]
    resources = ["*"]
  }

  statement {
    sid       = "PKIBuckets"
    actions   = ["s3:*"]
    resources = ["arn:${local.partition}:s3:::pki-*", "arn:${local.partition}:s3:::pki-*/*"]
  }

  statement {
    sid = "PKIRolesOnly"
    actions = [
      "iam:CreateRole", "iam:DeleteRole", "iam:GetRole", "iam:UpdateRole", "iam:TagRole", "iam:UntagRole",
      "iam:PutRolePolicy", "iam:GetRolePolicy", "iam:DeleteRolePolicy", "iam:ListRolePolicies",
      "iam:AttachRolePolicy", "iam:DetachRolePolicy", "iam:ListAttachedRolePolicies",
      "iam:UpdateAssumeRolePolicy", "iam:ListInstanceProfilesForRole", "iam:PassRole",
    ]
    resources = ["arn:${local.partition}:iam::${local.account_id}:role/pki-*"]
  }

  statement {
    sid       = "ServiceLinkedRoles"
    actions   = ["iam:CreateServiceLinkedRole"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "iam:AWSServiceName"
      values   = ["acm-pca.amazonaws.com", "pca-connector-ad.amazonaws.com", "ram.amazonaws.com"]
    }
  }

  # Destroying a CA is a break-glass action, never a pipeline action, even
  # if someone removes prevent_destroy from the code.
  statement {
    sid       = "NeverDeleteCAsOrExportKeys"
    effect    = "Deny"
    actions   = ["acm-pca:DeleteCertificateAuthority", "acm:ExportCertificate", "kms:ScheduleKeyDeletion"]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "apply" {
  name        = "hcp-terraform-pki-apply-${var.environment}"
  description = "Permissions of the HCP Terraform apply phase for PKI workspaces"
  policy      = data.aws_iam_policy_document.apply.json
}

resource "aws_iam_role" "apply" {
  name                 = "hcp-terraform-pki-apply-${var.environment}"
  description          = "HCP Terraform APPLY phase for PKI workspaces"
  assume_role_policy   = data.aws_iam_policy_document.apply_trust.json
  max_session_duration = 7200
}

resource "aws_iam_role_policy_attachment" "apply" {
  role       = aws_iam_role.apply.name
  policy_arn = aws_iam_policy.apply.arn
}

# Plan needs to read Lambda zips, bucket policies... ReadOnlyAccess covers it.
# Apply also needs read for refresh:
resource "aws_iam_role_policy_attachment" "apply_readonly" {
  role       = aws_iam_role.apply.name
  policy_arn = "arn:${local.partition}:iam::aws:policy/ReadOnlyAccess"
}

###############################################################################
# GitHub Actions OIDC (scheduled certificate inventory, read-only)
###############################################################################
resource "aws_iam_openid_connect_provider" "github" {
  count          = var.github_repository != null ? 1 : 0
  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]
}

data "aws_iam_policy_document" "github_trust" {
  count = var.github_repository != null ? 1 : 0

  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github[0].arn]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    # Only jobs bound to the GitHub environment "inventory-<env>" of this repo.
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:${var.github_repository}:environment:inventory-${var.environment}"]
    }
  }
}

resource "aws_iam_role" "github_inventory" {
  count              = var.github_repository != null ? 1 : 0
  name               = "github-pki-inventory-${var.environment}"
  description        = "GitHub Actions - read-only certificate inventory"
  assume_role_policy = data.aws_iam_policy_document.github_trust[0].json
}

resource "aws_iam_role_policy" "github_inventory" {
  #checkov:skip=CKV_AWS_355:List/Describe actions on all CAs and certificates are required for an inventory
  count = var.github_repository != null ? 1 : 0
  name  = "certificate-inventory"
  role  = aws_iam_role.github_inventory[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "acm:ListCertificates",
        "acm:DescribeCertificate",
        "acm:ListTagsForCertificate",
        "acm-pca:ListCertificateAuthorities",
        "acm-pca:DescribeCertificateAuthority",
        "acm-pca:GetCertificateAuthorityCertificate",
        "acm-pca:ListTags",
      ]
      Resource = "*"
    }]
  })
}
