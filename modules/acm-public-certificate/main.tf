###############################################################################
# Module: acm-public-certificate
#
# Publicly trusted certificate from Amazon's public CA, validated by DNS
# (Route 53). ACM renews it automatically as long as the validation CNAME
# records stay in place - NEVER delete them.
#
# Why it matters in 2026: CA/Browser Forum ballot SC-081v3 caps public TLS
# certificates at 200 days (since 2026-03-15), 100 days (2027-03-15) and
# 47 days (2029-03-15). Manual renewal of public certs is no longer viable;
# DNS-validated ACM certificates renew without human action.
###############################################################################

resource "aws_acm_certificate" "this" {
  domain_name               = var.domain_name
  subject_alternative_names = var.subject_alternative_names
  validation_method         = "DNS"
  key_algorithm             = var.key_algorithm

  options {
    certificate_transparency_logging_preference = "ENABLED" # public certs must be CT-logged to be trusted by browsers
  }

  tags = merge(var.tags, {
    "pki:owner"     = var.owner
    "pki:managed"   = "terraform"
    "pki:component" = "public-certificate"
  })

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_route53_record" "validation" {
  for_each = {
    for dvo in aws_acm_certificate.this.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }

  zone_id         = var.route53_zone_id
  name            = each.value.name
  type            = each.value.type
  records         = [each.value.record]
  ttl             = 300
  allow_overwrite = true
}

resource "aws_acm_certificate_validation" "this" {
  certificate_arn         = aws_acm_certificate.this.arn
  validation_record_fqdns = [for r in aws_route53_record.validation : r.fqdn]
}
