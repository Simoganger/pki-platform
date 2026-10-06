###############################################################################
# Example: short-lived mTLS certificates for Kubernetes pods (EKS)
#
#   cert-manager + aws-privateca-issuer (AWS-maintained plugin)
#     -> issues 1-7 day certificates from the SHORT_LIVED workloads CA
#     -> cert-manager renews them automatically at 2/3 of their lifetime
#
# Short-lived certificates are the modern answer to revocation: a stolen key
# is useless within days, without depending on CRL/OCSP checks.
#
# This Terraform creates the IAM role for the issuer (EKS Pod Identity).
# Install the charts with the values in ./helm and apply ./manifests.
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

variable "cluster_name" {
  description = "EKS cluster name."
  type        = string
}

variable "workloads_ca_arn" {
  description = "ARN of the SHORT_LIVED_CERTIFICATE issuing CA (shared to this account by RAM)."
  type        = string
}

data "aws_partition" "current" {}

data "aws_iam_policy_document" "trust" {
  statement {
    actions = ["sts:AssumeRole", "sts:TagSession"]
    principals {
      type        = "Service"
      identifiers = ["pods.eks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "pca_issuer" {
  name               = "pki-${var.cluster_name}-aws-privateca-issuer"
  assume_role_policy = data.aws_iam_policy_document.trust.json
}

resource "aws_iam_role_policy" "pca_issuer" {
  name = "issue-from-workloads-ca"
  role = aws_iam_role.pca_issuer.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "DescribeCA"
        Effect   = "Allow"
        Action   = ["acm-pca:DescribeCertificateAuthority"]
        Resource = var.workloads_ca_arn
      },
      {
        Sid      = "IssueOnlyEndEntityCertificates"
        Effect   = "Allow"
        Action   = ["acm-pca:IssueCertificate", "acm-pca:GetCertificate"]
        Resource = var.workloads_ca_arn
        Condition = {
          ArnLike = {
            "acm-pca:TemplateArn" = [
              "arn:${data.aws_partition.current.partition}:acm-pca:::template/EndEntityCertificate/V1",
              "arn:${data.aws_partition.current.partition}:acm-pca:::template/EndEntityClientAuthCertificate/V1",
              "arn:${data.aws_partition.current.partition}:acm-pca:::template/EndEntityServerAuthCertificate/V1",
            ]
          }
        }
      }
    ]
  })
}

resource "aws_eks_pod_identity_association" "pca_issuer" {
  cluster_name    = var.cluster_name
  namespace       = "cert-manager"
  service_account = "aws-privateca-issuer"
  role_arn        = aws_iam_role.pca_issuer.arn
}

output "issuer_role_arn" {
  description = "Role used by the aws-privateca-issuer service account."
  value       = aws_iam_role.pca_issuer.arn
}
