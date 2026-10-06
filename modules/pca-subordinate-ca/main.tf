###############################################################################
# Module: pca-subordinate-ca
#
# Creates an ISSUING (subordinate) CA in AWS Private CA. This is the CA that
# actually signs end-entity certificates for servers, workloads and devices.
#
# TWO SIGNING MODES
#
#   signing_mode = "PCA"       Parent CA is another AWS Private CA (lab / nonprod
#                              root created by module pca-root-ca). Fully automatic,
#                              single apply.
#
#   signing_mode = "EXTERNAL"  Parent is an OFFLINE root in an on-prem HSM
#                              (production pattern). Two applies:
#                                1) apply -> CA is created in PENDING_CERTIFICATE
#                                   state and its CSR is exposed in output `csr_pem`.
#                                2) The CSR is signed during a key ceremony
#                                   (docs/runbooks/external-root-signing.md),
#                                   then the signed cert + chain are set in
#                                   `external_signed_certificate` and applied.
#
# OPTIONAL HARDENING
#   - Name constraints (RFC 5280 4.2.1.10): restricts which DNS names this CA
#     can ever sign. Clients reject any certificate outside the permitted
#     subtrees. Build the DER value with scripts/build_name_constraints.py.
#   - OCSP (AWS-managed responder) in addition to the CRL.
#   - ACM permission so ACM can issue and AUTO-RENEW private certificates.
###############################################################################

data "aws_partition" "current" {}

locals {
  partition = data.aws_partition.current.partition

  use_name_constraints = var.name_constraints_der_base64 != null

  # Blank APIPassthrough template = we provide the extensions (name constraints).
  subordinate_template_arn = local.use_name_constraints ? (
    "arn:${local.partition}:acm-pca:::template/BlankSubordinateCACertificate_PathLen0_APIPassthrough/V1"
    ) : (
    "arn:${local.partition}:acm-pca:::template/SubordinateCACertificate_PathLen0/V1"
  )

  api_passthrough = local.use_name_constraints ? jsonencode({
    Extensions = {
      KeyUsage = {
        DigitalSignature = true
        KeyCertSign      = true
        CRLSign          = true
      }
      CustomExtensions = [{
        ObjectIdentifier = "2.5.29.30" # id-ce-nameConstraints
        Value            = var.name_constraints_der_base64
        Critical         = true
      }]
    }
  }) : null

  install_external = var.signing_mode == "EXTERNAL" && var.external_signed_certificate != null

  tags = merge(var.tags, {
    "pki:ca-role"    = "issuing"
    "pki:ca-name"    = var.name
    "pki:usage"      = var.usage
    "pki:usage-mode" = var.usage_mode
    "pki:managed"    = "terraform"
    "pki:component"  = "certificate-authority"
  })
}

resource "aws_acmpca_certificate_authority" "this" {
  type                          = "SUBORDINATE"
  usage_mode                    = var.usage_mode
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
      s3_object_acl      = var.crl.enabled ? "BUCKET_OWNER_FULL_CONTROL" : null
      custom_cname       = var.crl.enabled ? var.crl.custom_cname : null
    }

    ocsp_configuration {
      enabled           = var.ocsp.enabled
      ocsp_custom_cname = var.ocsp.enabled ? var.ocsp.custom_cname : null
    }
  }

  permanent_deletion_time_in_days = var.permanent_deletion_time_in_days
  enabled                         = var.enabled
  tags                            = local.tags

  lifecycle {
    prevent_destroy = true
  }
}

###############################################################################
# Mode PCA: the parent is an AWS Private CA in the same account
###############################################################################
resource "aws_acmpca_certificate" "signed_by_pca_parent" {
  count = var.signing_mode == "PCA" ? 1 : 0

  certificate_authority_arn   = var.parent_ca_arn
  certificate_signing_request = aws_acmpca_certificate_authority.this.certificate_signing_request
  signing_algorithm           = var.parent_signing_algorithm
  template_arn                = local.subordinate_template_arn
  api_passthrough             = local.api_passthrough

  validity {
    type  = "YEARS"
    value = var.validity_years
  }

  lifecycle {
    precondition {
      condition     = var.parent_ca_arn != null && var.parent_signing_algorithm != null
      error_message = "signing_mode = PCA requires parent_ca_arn and parent_signing_algorithm."
    }
  }
}

resource "aws_acmpca_certificate_authority_certificate" "pca_parent" {
  count = var.signing_mode == "PCA" ? 1 : 0

  certificate_authority_arn = aws_acmpca_certificate_authority.this.arn
  certificate               = aws_acmpca_certificate.signed_by_pca_parent[0].certificate
  certificate_chain         = aws_acmpca_certificate.signed_by_pca_parent[0].certificate_chain
}

###############################################################################
# Mode EXTERNAL: certificate signed offline by the HSM-protected root
###############################################################################
resource "aws_acmpca_certificate_authority_certificate" "external" {
  count = local.install_external ? 1 : 0

  certificate_authority_arn = aws_acmpca_certificate_authority.this.arn
  certificate               = var.external_signed_certificate.certificate_pem
  certificate_chain         = var.external_signed_certificate.certificate_chain_pem
}

###############################################################################
# Let ACM issue and AUTO-RENEW private certificates from this CA.
# Without this permission ACM can issue the first certificate but managed
# renewal fails silently ("ACM Certificate Renewal Action Required").
###############################################################################
resource "aws_acmpca_permission" "acm" {
  count = var.allow_acm_managed_renewal ? 1 : 0

  certificate_authority_arn = aws_acmpca_certificate_authority.this.arn
  actions                   = ["IssueCertificate", "GetCertificate", "ListPermissions"]
  principal                 = "acm.amazonaws.com"
  source_account            = data.aws_caller_identity.current.account_id
}

data "aws_caller_identity" "current" {}

###############################################################################
# Optional resource policy (needed when the CA is shared through AWS RAM and you
# want to restrict which templates consumer accounts may use).
###############################################################################
resource "aws_acmpca_policy" "this" {
  count = var.resource_policy_json != null ? 1 : 0

  resource_arn = aws_acmpca_certificate_authority.this.arn
  policy       = var.resource_policy_json
}
