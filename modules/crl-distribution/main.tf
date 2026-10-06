###############################################################################
# Module: crl-distribution
#
# Publishes CRLs written by AWS Private CA to a private S3 bucket and serves
# them over HTTP through CloudFront.
#
# WHY THIS DESIGN
#   - The CRL Distribution Point (CDP) URL is embedded in EVERY certificate a CA
#     issues. It must stay reachable for the life of those certificates, so it
#     points to a stable DNS name you own (crl.pki.example.com), never to a raw
#     bucket URL.
#   - CRLs are served over plain HTTP on purpose: a client validating an HTTPS
#     certificate cannot depend on HTTPS to fetch revocation data (circular
#     dependency). CRLs are signed, so integrity does not rely on TLS.
#   - The bucket keeps S3 Block Public Access ON. PCA writes with
#     BUCKET_OWNER_FULL_CONTROL; only CloudFront (Origin Access Control) reads.
#
# OBJECT LAYOUT (written by PCA):   crl/<ca-id>.crl
###############################################################################

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
  region     = data.aws_region.current.region
}

resource "aws_s3_bucket" "crl" {
  #checkov:skip=CKV_AWS_145:CRLs are public signed objects; SSE-S3 keeps CloudFront OAC simple
  bucket        = var.bucket_name
  force_destroy = false
  tags          = merge(var.tags, { "pki:component" = "crl-distribution" })
}

resource "aws_s3_bucket_public_access_block" "crl" {
  bucket                  = aws_s3_bucket.crl.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "crl" {
  bucket = aws_s3_bucket.crl.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "crl" {
  bucket = aws_s3_bucket.crl.id
  versioning_configuration {
    status = "Enabled" # keeps previous CRLs: useful for forensics
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "crl" {
  bucket = aws_s3_bucket.crl.id
  rule {
    # SSE-S3: CloudFront OAC cannot read SSE-KMS objects without extra key policy,
    # and CRLs are public data anyway.
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "crl" {
  bucket = aws_s3_bucket.crl.id
  rule {
    id     = "expire-old-crl-versions"
    status = "Enabled"
    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
    noncurrent_version_expiration {
      noncurrent_days = var.noncurrent_crl_retention_days
    }
  }
}

resource "aws_s3_bucket_logging" "crl" {
  count         = var.access_log_bucket != null ? 1 : 0
  bucket        = aws_s3_bucket.crl.id
  target_bucket = var.access_log_bucket
  target_prefix = "s3/${var.bucket_name}/"
}

data "aws_iam_policy_document" "crl" {
  statement {
    sid     = "AllowPrivateCAToWriteCRLs"
    effect  = "Allow"
    actions = ["s3:PutObject", "s3:PutObjectAcl", "s3:GetBucketAcl", "s3:GetBucketLocation"]
    resources = [
      aws_s3_bucket.crl.arn,
      "${aws_s3_bucket.crl.arn}/*",
    ]
    principals {
      type        = "Service"
      identifiers = ["acm-pca.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:${local.partition}:acm-pca:${local.region}:${local.account_id}:certificate-authority/*"]
    }
  }

  statement {
    sid       = "AllowCloudFrontReadCRLs"
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.crl.arn}/crl/*"]
    principals {
      type        = "Service"
      identifiers = ["cloudfront.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "AWS:SourceArn"
      values   = [aws_cloudfront_distribution.crl.arn]
    }
  }

  statement {
    sid       = "DenyInsecureTransportForAPI"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.crl.arn, "${aws_s3_bucket.crl.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "crl" {
  bucket = aws_s3_bucket.crl.id
  policy = data.aws_iam_policy_document.crl.json

  depends_on = [aws_s3_bucket_public_access_block.crl]
}

###############################################################################
# CloudFront
###############################################################################
resource "aws_cloudfront_origin_access_control" "crl" {
  name                              = "${var.bucket_name}-oac"
  description                       = "OAC for PKI CRL bucket"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

# AWS managed cache policy "CachingOptimized" would cache up to 1 year; CRLs
# change every few hours, so we use a short custom TTL.
resource "aws_cloudfront_cache_policy" "crl" {
  name        = "${var.bucket_name}-crl-cache"
  default_ttl = var.cache_ttl_seconds
  max_ttl     = var.cache_ttl_seconds
  min_ttl     = 0

  parameters_in_cache_key_and_forwarded_to_origin {
    cookies_config {
      cookie_behavior = "none"
    }
    headers_config {
      header_behavior = "none"
    }
    query_strings_config {
      query_string_behavior = "none"
    }
  }
}

resource "aws_cloudfront_distribution" "crl" {
  #checkov:skip=CKV_AWS_305:No root object: the distribution only serves /crl/<id>.crl
  #checkov:skip=CKV_AWS_174:TLS 1.2 minimum is set when an alias certificate is used; the default *.cloudfront.net certificate does not allow setting it
  enabled         = true
  is_ipv6_enabled = true
  comment         = "PKI CRL distribution point"
  aliases         = var.aliases
  price_class     = var.price_class

  origin {
    domain_name              = aws_s3_bucket.crl.bucket_regional_domain_name
    origin_id                = "crl-s3"
    origin_access_control_id = aws_cloudfront_origin_access_control.crl.id
  }

  default_cache_behavior {
    target_origin_id = "crl-s3"
    allowed_methods  = ["GET", "HEAD"]
    cached_methods   = ["GET", "HEAD"]
    # allow-all: CRL clients (Windows CAPI, OpenSSL, Java) fetch over HTTP.
    viewer_protocol_policy = "allow-all" #checkov:skip=CKV_AWS_34:CRLs must be reachable over HTTP (RFC 5280); they are signed objects.
    cache_policy_id        = aws_cloudfront_cache_policy.crl.id
    compress               = false
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    # A certificate is required by CloudFront for any alias, even if clients use HTTP.
    acm_certificate_arn            = length(var.aliases) > 0 ? var.alias_acm_certificate_arn_us_east_1 : null
    cloudfront_default_certificate = length(var.aliases) == 0
    ssl_support_method             = length(var.aliases) > 0 ? "sni-only" : null
    minimum_protocol_version       = length(var.aliases) > 0 ? "TLSv1.2_2021" : null
  }

  dynamic "logging_config" {
    for_each = var.access_log_bucket != null ? [1] : []
    content {
      bucket = "${var.access_log_bucket}.s3.amazonaws.com"
      prefix = "cloudfront/${var.bucket_name}/"
    }
  }

  tags = merge(var.tags, { "pki:component" = "crl-distribution" })

  lifecycle {
    precondition {
      condition     = length(var.aliases) == 0 || var.alias_acm_certificate_arn_us_east_1 != null
      error_message = "aliases require alias_acm_certificate_arn_us_east_1 (ACM certificate in us-east-1)."
    }
  }
}

###############################################################################
# DNS (optional)
###############################################################################
resource "aws_route53_record" "crl" {
  for_each = var.route53_zone_id != null ? toset(var.aliases) : toset([])

  zone_id = var.route53_zone_id
  name    = each.value
  type    = "A"

  alias {
    name                   = aws_cloudfront_distribution.crl.domain_name
    zone_id                = aws_cloudfront_distribution.crl.hosted_zone_id
    evaluate_target_health = false
  }
}
