###############################################################################
# Module: pca-ram-share
#
# Shares one or more issuing CAs with other AWS accounts / OUs through AWS
# Resource Access Manager. Consumer accounts can then ISSUE certificates
# (directly or through ACM) but can never administer, disable or delete the CA.
#
# This is the "vending machine" distribution mechanism: the PKI account owns
# the CAs; workload accounts consume them.
#
# RAM managed permissions for AWS Private CA (pick the narrowest):
#   AWSRAMDefaultPermissionCertificateAuthority        -> end-entity certs (default)
#   AWSRAMBlankEndEntityCertificateAPICSRPassthroughIssuanceCertificateAuthority
#   AWSRAMSubordinateCACertificatePathLen0IssuanceCertificateAuthority (lets the
#     consumer create subordinate CAs - almost never what you want)
###############################################################################

data "aws_partition" "current" {}

locals {
  default_permission = "arn:${data.aws_partition.current.partition}:ram::aws:permission/AWSRAMDefaultPermissionCertificateAuthority"
}

resource "aws_ram_resource_share" "this" {
  name = var.name

  # Never share PKI outside the AWS Organization.
  allow_external_principals = false

  permission_arns = length(var.permission_arns) > 0 ? var.permission_arns : [local.default_permission]

  tags = merge(var.tags, { "pki:component" = "ram-share" })
}

resource "aws_ram_resource_association" "ca" {
  # count (not for_each): CA ARNs are unknown until the CAs exist, and
  # for_each keys must be known at plan time.
  count = length(var.certificate_authority_arns)

  resource_share_arn = aws_ram_resource_share.this.arn
  resource_arn       = var.certificate_authority_arns[count.index]
}

resource "aws_ram_principal_association" "principal" {
  for_each = toset(var.principals)

  resource_share_arn = aws_ram_resource_share.this.arn
  principal          = each.value
}
