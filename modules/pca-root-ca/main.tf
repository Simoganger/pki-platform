###############################################################################
# Module: pca-root-ca
#
# Creates a ROOT certificate authority in AWS Private CA and self-signs it.
#
# WHEN TO USE
#   - Non-production / lab PKI hierarchies.
#   - Production ONLY if your CP/CPS allows a cloud-hosted root. In most
#     regulated banks the production root stays OFFLINE in an on-premises HSM
#     (Thales Luna / Utimaco) and AWS hosts only the issuing CAs - see the
#     `pca-subordinate-ca` module with `signing_mode = "EXTERNAL"`.
#
# WHAT IT CREATES
#   1. aws_acmpca_certificate_authority             (type = ROOT)
#   2. aws_acmpca_certificate                       (self-signed root cert)
#   3. aws_acmpca_certificate_authority_certificate (installs the cert -> CA becomes ACTIVE)
###############################################################################

data "aws_partition" "current" {}

locals {
  root_template_arn = "arn:${data.aws_partition.current.partition}:acm-pca:::template/RootCACertificate/V1"

  tags = merge(var.tags, {
    "pki:ca-role"   = "root"
    "pki:ca-name"   = var.name
    "pki:managed"   = "terraform"
    "pki:component" = "certificate-authority"
  })
}

resource "aws_acmpca_certificate_authority" "this" {
  type       = "ROOT"
  usage_mode = "GENERAL_PURPOSE" # a root signs CAs and CRLs, never short-lived leaf certs

  # Keys of an AWS Private CA live in AWS-managed HSMs and are never exportable.
  key_storage_security_standard = var.key_storage_security_standard

  certificate_authority_configuration {
    key_algorithm     = var.key_algorithm
    signing_algorithm = var.signing_algorithm

    subject {
      common_name         = var.subject.common_name
      organization        = var.subject.organization
      organizational_unit = var.subject.organizational_unit
      country             = var.subject.country
      state               = var.subject.state
      locality            = var.subject.locality
    }
  }

  revocation_configuration {
    crl_configuration {
      enabled            = var.crl.enabled
      expiration_in_days = var.crl.expiration_in_days
      s3_bucket_name     = var.crl.enabled ? var.crl.s3_bucket_name : null
      # BUCKET_OWNER_FULL_CONTROL lets the CRL bucket keep S3 Block Public Access ON;
      # CRLs are then served through CloudFront (see module crl-distribution).
      s3_object_acl = var.crl.enabled ? "BUCKET_OWNER_FULL_CONTROL" : null
      custom_cname  = var.crl.enabled ? var.crl.custom_cname : null
    }
  }

  # A deleted CA can be restored during this window. Use the maximum (30)
  # for anything that matters: deleting a CA breaks every certificate it issued.
  permanent_deletion_time_in_days = var.permanent_deletion_time_in_days

  enabled = true
  tags    = local.tags

  lifecycle {
    # Never let a plan silently destroy a root CA.
    prevent_destroy = true
  }
}

resource "aws_acmpca_certificate" "this" {
  certificate_authority_arn   = aws_acmpca_certificate_authority.this.arn
  certificate_signing_request = aws_acmpca_certificate_authority.this.certificate_signing_request
  signing_algorithm           = var.signing_algorithm
  template_arn                = local.root_template_arn

  validity {
    type  = "YEARS"
    value = var.validity_years
  }
}

resource "aws_acmpca_certificate_authority_certificate" "this" {
  certificate_authority_arn = aws_acmpca_certificate_authority.this.arn
  certificate               = aws_acmpca_certificate.this.certificate
  certificate_chain         = aws_acmpca_certificate.this.certificate_chain
}
