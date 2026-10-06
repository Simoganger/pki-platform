###############################################################################
# Workspace: pki-core-prod      (AWS account: PKI production)
#
#   OFFLINE ROOT CA (on-prem HSM - Thales Luna / Utimaco, never in AWS)
#     |  signs, during a key ceremony, the CSR of each issuing CA below
#     |-- servers-issuing-g1   AWS Private CA, GENERAL_PURPOSE
#     |-- pci-issuing-g1       AWS Private CA, GENERAL_PURPOSE, name constraints = PCI zone only
#     |-- workloads-mtls-g1    AWS Private CA, SHORT_LIVED_CERTIFICATE
#     `-- windows-issuing-g1   AWS Private CA (Connector for AD)
#
# TWO-PHASE LIFECYCLE OF AN ISSUING CA (signing_mode = EXTERNAL)
#   Phase 1  PR adds the CA to var.issuing_cas -> apply -> CA is PENDING_CERTIFICATE
#            -> `terraform output -json issuing_ca_csrs` gives the CSR.
#   Ceremony CSR signed by the offline root (docs/runbooks/external-root-signing.md).
#   Phase 2  PR adds ceremony/signed/<ca-key>.pem (public certificate, safe to
#            commit and reviewable) -> apply -> certificate installed, CA ACTIVE.
#
# The root certificate itself (public) lives in ceremony/root-ca.pem.
###############################################################################

locals {
  name_prefix = "pki-${var.environment}"

  default_tags = {
    environment         = var.environment
    owner               = var.owner_email
    data_classification = "restricted"
    cost_center         = var.cost_center
    pci_scope           = "connected"
    repository          = "pki-platform"
    managed_by          = "terraform"
  }

  repo_root    = "${path.root}/../../.."
  ceremony_dir = "${path.module}/ceremony"
  root_ca_pem  = fileexists("${local.ceremony_dir}/root-ca.pem") ? file("${local.ceremony_dir}/root-ca.pem") : null
  signed_cert  = { for k, _ in var.issuing_cas : k => "${local.ceremony_dir}/signed/${k}.pem" }
  ca_is_signed = { for k, p in local.signed_cert : k => fileexists(p) && local.root_ca_pem != null }
}

data "aws_caller_identity" "current" {}

###############################################################################
# 1. CRL distribution point (stable public hostname is mandatory in prod)
###############################################################################
module "crl_alias_certificate" {
  source = "../../../modules/acm-public-certificate"

  providers = {
    aws = aws.us_east_1
  }

  domain_name     = var.crl_hostname
  route53_zone_id = var.public_route53_zone_id
  owner           = var.owner_email
}

module "crl" {
  source = "../../../modules/crl-distribution"

  bucket_name                         = "${local.name_prefix}-crl-${data.aws_caller_identity.current.account_id}"
  aliases                             = [var.crl_hostname]
  alias_acm_certificate_arn_us_east_1 = module.crl_alias_certificate.arn
  route53_zone_id                     = var.public_route53_zone_id
  access_log_bucket                   = var.access_log_bucket
}

###############################################################################
# 2. Issuing CAs signed by the offline root
###############################################################################
module "issuing_ca" {
  source   = "../../../modules/pca-subordinate-ca"
  for_each = var.issuing_cas

  name       = "${local.name_prefix}-${each.key}"
  usage      = each.value.usage
  usage_mode = each.value.usage_mode
  subject = {
    common_name         = each.value.common_name
    organization        = var.organization_name
    organizational_unit = "Data Protection - PKI"
    country             = "CA"
  }

  key_algorithm     = each.value.key_algorithm
  signing_algorithm = each.value.signing_algorithm

  signing_mode = "EXTERNAL"
  external_signed_certificate = local.ca_is_signed[each.key] ? {
    certificate_pem       = file(local.signed_cert[each.key])
    certificate_chain_pem = local.root_ca_pem
  } : null

  # Name constraints are embedded by the OFFLINE root at signing time (the
  # ceremony uses the extension built by scripts/build_name_constraints.py);
  # nothing to pass here in EXTERNAL mode.

  allow_acm_managed_renewal = each.value.usage_mode == "GENERAL_PURPOSE"

  crl = {
    s3_bucket_name     = module.crl.bucket_name
    custom_cname       = var.crl_hostname
    expiration_in_days = each.value.crl_expiration_days
  }

  ocsp = {
    enabled      = each.value.ocsp_enabled
    custom_cname = each.value.ocsp_enabled ? var.ocsp_hostname : null
  }

  tags = each.value.usage == "pci" ? { pci_scope = "in-scope" } : {}

  depends_on = [module.crl]
}

###############################################################################
# 3. Vending machine (only ACTIVE CAs are shared)
###############################################################################
module "ram_share" {
  source = "../../../modules/pca-ram-share"
  for_each = {
    for k, v in var.issuing_cas : k => v
    if length(v.share_with) > 0 && local.ca_is_signed[k]
  }

  name                       = "${local.name_prefix}-${each.key}"
  certificate_authority_arns = [module.issuing_ca[each.key].arn]
  principals                 = each.value.share_with
}

###############################################################################
# 4. Monitoring + redistribution
###############################################################################
module "monitoring" {
  source = "../../../modules/pki-monitoring"

  name_prefix            = local.name_prefix
  alert_emails           = var.alert_emails
  alert_https_endpoints  = var.alert_https_endpoints
  crl_checker_source_dir = "${local.repo_root}/lambda/crl_freshness_checker"
  crl_urls = merge(
    { for k, ca in module.issuing_ca : k => ca.crl_url if local.ca_is_signed[k] },
    var.offline_root_crl_url != null ? { offline-root = var.offline_root_crl_url } : {},
  )
}

module "renewal_distributor" {
  source = "../../../modules/acm-renewal-distributor"

  name_prefix            = local.name_prefix
  lambda_source_dir      = "${local.repo_root}/lambda/dist/acm_renewal_distributor"
  notification_topic_arn = module.monitoring.alerts_topic_arn
}

###############################################################################
# 5. OCSP hostname (CNAME to the AWS-managed responder)
###############################################################################
resource "aws_route53_record" "ocsp" {
  count = var.ocsp_hostname != null ? 1 : 0

  zone_id = var.public_route53_zone_id
  name    = var.ocsp_hostname
  type    = "CNAME"
  ttl     = 300
  records = ["ocsp.acm-pca.${var.region}.amazonaws.com"]
}
