###############################################################################
# Module: acm-private-certificate   (the "building block" teams consume)
#
# Requests a PRIVATE certificate in AWS Certificate Manager, issued by an AWS
# Private CA (owned by this account or shared through RAM).
#
# AUTO-RENEWAL
#   ACM renews private certificates automatically before expiry (managed
#   renewal) as long as:
#     1. the issuing CA is ACTIVE and GENERAL_PURPOSE (ACM cannot use a
#        SHORT_LIVED_CERTIFICATE CA),
#     2. acm.amazonaws.com has IssueCertificate/GetCertificate/ListPermissions
#        on the CA (module pca-subordinate-ca: allow_acm_managed_renewal), and
#     3. for integrated services (ALB, NLB, CloudFront, API Gateway) - nothing
#        else to do: the renewed cert is deployed transparently.
#   For EC2 / on-prem / containers that use an EXPORTED copy, ACM emits
#   "ACM Certificate Available" after renewal; module acm-renewal-distributor
#   catches it and redistributes the new certificate.
#
# GUARDRAILS BUILT IN
#   - Every name must end with one of `allowed_domain_suffixes` (no wildcard
#     unless allow_wildcard = true). This mirrors the CA name constraints and
#     gives a clear error at PLAN time instead of a rejected certificate later.
#   - Mandatory owner tag so expiry alerts reach a human.
###############################################################################

locals {
  all_names = concat([var.domain_name], var.subject_alternative_names)

  names_allowed = alltrue([
    for n in local.all_names : anytrue([
      # exact match or a real sub-domain (".example.com"), so "evilexample.com" is rejected
      for s in var.allowed_domain_suffixes :
      trimprefix(n, "*.") == trimprefix(s, ".") || endswith(trimprefix(n, "*."), ".${trimprefix(s, ".")}")
    ])
  ])

  has_wildcard = anytrue([for n in local.all_names : startswith(n, "*.")])

  distribution_tags = var.distribution != null ? {
    "pki:distribute"     = var.distribution.method
    "pki:secret-name"    = coalesce(var.distribution.secret_name, "pki/certs/${replace(var.domain_name, "*.", "wildcard.")}")
    "pki:reader-role"    = var.distribution.reader_role_arn
    "pki:ssm-target-tag" = coalesce(var.distribution.ssm_target_tag_value, "")
  } : {}

  tags = merge(var.tags, local.distribution_tags, {
    "pki:owner"     = var.owner
    "pki:app"       = var.application
    "pki:managed"   = "terraform"
    "pki:component" = "certificate"
  })
}

resource "aws_acm_certificate" "this" {
  domain_name               = var.domain_name
  subject_alternative_names = var.subject_alternative_names
  certificate_authority_arn = var.certificate_authority_arn
  key_algorithm             = var.key_algorithm

  tags = local.tags

  lifecycle {
    # Replacing a certificate attached to a load balancer must create the new
    # one first, otherwise the listener loses its certificate.
    create_before_destroy = true

    precondition {
      condition     = local.names_allowed
      error_message = "One or more names are outside allowed_domain_suffixes (${join(", ", var.allowed_domain_suffixes)}). Request this domain through the PKI team."
    }

    precondition {
      condition     = var.allow_wildcard || !local.has_wildcard
      error_message = "Wildcard certificates are not allowed by default (blast radius). Set allow_wildcard = true only with a PKI exception ticket."
    }
  }
}

###############################################################################
# Per-certificate expiry alarm (belt and braces: ACM should renew long before).
###############################################################################
resource "aws_cloudwatch_metric_alarm" "days_to_expiry" {
  count = var.expiry_alarm.enabled ? 1 : 0

  alarm_name          = "pki-cert-expiry-${replace(var.domain_name, "*", "wildcard")}"
  alarm_description   = "ACM certificate ${var.domain_name} (owner ${var.owner}) expires in less than ${var.expiry_alarm.threshold_days} days - managed renewal has probably failed. Runbook: docs/runbooks/certificate-renewal-failure.md"
  namespace           = "AWS/CertificateManager"
  metric_name         = "DaysToExpiry"
  statistic           = "Minimum"
  period              = 86400
  evaluation_periods  = 1
  comparison_operator = "LessThanThreshold"
  threshold           = var.expiry_alarm.threshold_days
  treat_missing_data  = "breaching" # no data = we cannot prove it is fine

  dimensions = {
    CertificateArn = aws_acm_certificate.this.arn
  }

  alarm_actions = var.expiry_alarm.sns_topic_arns
  ok_actions    = var.expiry_alarm.sns_topic_arns
  tags          = local.tags
}
