###############################################################################
# Workspace: pki-core-nonprod      (AWS account: PKI non-production)
#
#   Root CA (AWS Private CA, nonprod only)
#     |-- servers-issuing-g1    GENERAL_PURPOSE  -> ACM private certs, auto-renew
#     |-- workloads-mtls-g1     SHORT_LIVED      -> 7-day certs for service mesh / pods
#     `-- windows-issuing-g1    GENERAL_PURPOSE  -> Connector for AD auto-enrollment
#
#   + CRL distribution point (S3 + CloudFront)
#   + RAM shares to workload OUs (vending machine)
#   + monitoring (EventBridge, SNS, CRL freshness) and renewal distributor
###############################################################################

locals {
  name_prefix = "pki-${var.environment}"

  default_tags = {
    environment         = var.environment
    owner               = var.owner_email
    data_classification = "confidential"
    cost_center         = var.cost_center
    repository          = "pki-platform"
    managed_by          = "terraform"
  }

  repo_root = "${path.root}/../../.."
}

###############################################################################
# 1. CRL distribution point
###############################################################################
module "crl_alias_certificate" {
  source = "../../../modules/acm-public-certificate"
  count  = var.crl_hostname != null ? 1 : 0

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
  aliases                             = var.crl_hostname != null ? [var.crl_hostname] : []
  alias_acm_certificate_arn_us_east_1 = try(module.crl_alias_certificate[0].arn, null)
  route53_zone_id                     = var.crl_hostname != null ? var.public_route53_zone_id : null
}

data "aws_caller_identity" "current" {}

###############################################################################
# 2. Root CA (non-production only - production root is OFFLINE, see prod/)
###############################################################################
module "root_ca" {
  source = "../../../modules/pca-root-ca"

  name = "${local.name_prefix}-root-g1"
  subject = {
    common_name         = "${var.organization_name} NonProd Root CA G1"
    organization        = var.organization_name
    organizational_unit = "Data Protection - PKI"
    country             = "CA"
    state               = "Quebec"
    locality            = "Montreal"
  }

  key_algorithm     = "RSA_4096"
  signing_algorithm = "SHA512WITHRSA"
  validity_years    = 10

  crl = {
    s3_bucket_name     = module.crl.bucket_name
    custom_cname       = module.crl.cdp_hostname
    expiration_in_days = 365
  }

  depends_on = [module.crl] # bucket policy must exist before PCA validates the bucket
}

###############################################################################
# 3. Issuing CAs (one per usage / risk zone)
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
  validity_years    = each.value.validity_years

  signing_mode             = "PCA"
  parent_ca_arn            = module.root_ca.arn
  parent_signing_algorithm = module.root_ca.signing_algorithm

  name_constraints_der_base64 = each.value.name_constraints_der_base64

  # ACM cannot use SHORT_LIVED CAs, so only grant the ACM permission where useful.
  allow_acm_managed_renewal = each.value.usage_mode == "GENERAL_PURPOSE"

  crl = {
    s3_bucket_name     = module.crl.bucket_name
    custom_cname       = module.crl.cdp_hostname
    expiration_in_days = each.value.crl_expiration_days
  }

  ocsp = {
    enabled = each.value.ocsp_enabled
  }

  depends_on = [module.root_ca]
}

###############################################################################
# 4. Vending machine: share the issuing CAs with workload OUs
###############################################################################
module "ram_share" {
  source   = "../../../modules/pca-ram-share"
  for_each = { for k, v in var.issuing_cas : k => v if length(v.share_with) > 0 }

  name                       = "${local.name_prefix}-${each.key}"
  certificate_authority_arns = [module.issuing_ca[each.key].arn]
  principals                 = each.value.share_with
}

###############################################################################
# 5. Monitoring + auto-renewal redistribution
###############################################################################
module "monitoring" {
  source = "../../../modules/pki-monitoring"

  name_prefix            = local.name_prefix
  alert_emails           = var.alert_emails
  alert_https_endpoints  = var.alert_https_endpoints
  crl_checker_source_dir = "${local.repo_root}/lambda/crl_freshness_checker"
  crl_urls = merge(
    { for k, ca in module.issuing_ca : k => ca.crl_url },
    { root-g1 = "http://${module.crl.cdp_hostname}/crl/${module.root_ca.id}.crl" },
  )
}

module "renewal_distributor" {
  source = "../../../modules/acm-renewal-distributor"

  name_prefix            = local.name_prefix
  lambda_source_dir      = "${local.repo_root}/lambda/dist/acm_renewal_distributor"
  notification_topic_arn = module.monitoring.alerts_topic_arn
}
