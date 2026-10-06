###############################################################################
# Module: pki-audit-logging
#
# Tamper-evident audit trail for the PKI account (PCI DSS requirement 10):
#
#   CloudTrail (multi-region, log file validation, KMS)
#     -> S3 bucket (versioned, optional Object Lock = WORM)
#          -> SNS -> SQS  : Splunk Add-on for AWS "SQS-based S3" input pulls
#                           every new CloudTrail file (role + external ID below)
#     -> CloudWatch Logs  : metric filters on sensitive AWS Private CA / ACM /
#                           KMS / CloudTrail API calls -> alarms -> SNS
#
# The metric filters are the "tripwires": any destructive or trust-changing
# call (delete/disable a CA, change its policy or permissions, stop logging)
# that does NOT come from the HCP Terraform apply role raises an alarm.
###############################################################################

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
  region     = data.aws_region.current.region
  trail_arn  = "arn:${local.partition}:cloudtrail:${local.region}:${local.account_id}:trail/${var.trail_name}"
  tags       = merge(var.tags, { "pki:component" = "audit-logging" })

  # Each tripwire: CloudWatch Logs filter pattern on CloudTrail JSON.
  # Calls made by the pipeline role are excluded so only out-of-band changes alarm.
  # userIdentity.arn exists for root, IAM users and assumed roles, so an absent
  # field cannot silently suppress the alarm (a != on a missing field is false).
  pipeline_exclusion = join(" && ", [for p in var.trusted_automation_role_name_patterns : "$.userIdentity.arn != \"*:assumed-role/${p}\""])

  tripwires = {
    pca-destructive = {
      description = "AWS Private CA deleted, disabled, restored or its certificate replaced outside the pipeline"
      pattern     = "{ ($.eventSource = \"acm-pca.amazonaws.com\") && (($.eventName = \"DeleteCertificateAuthority\") || ($.eventName = \"UpdateCertificateAuthority\") || ($.eventName = \"RestoreCertificateAuthority\") || ($.eventName = \"ImportCertificateAuthorityCertificate\")) && ${local.pipeline_exclusion} }"
    }
    pca-trust-change = {
      description = "AWS Private CA permissions or resource policy changed outside the pipeline"
      pattern     = "{ ($.eventSource = \"acm-pca.amazonaws.com\") && (($.eventName = \"CreatePermission\") || ($.eventName = \"DeletePermission\") || ($.eventName = \"PutPolicy\") || ($.eventName = \"DeletePolicy\")) && ${local.pipeline_exclusion} }"
    }
    pca-revocation = {
      description = "A certificate was revoked (always reviewed)"
      pattern     = "{ ($.eventSource = \"acm-pca.amazonaws.com\") && ($.eventName = \"RevokeCertificate\") }"
    }
    acm-export = {
      description = "Private key exported from ACM by an identity other than the renewal distributor"
      pattern     = "{ ($.eventSource = \"acm.amazonaws.com\") && ($.eventName = \"ExportCertificate\") && ($.userIdentity.arn != \"*:assumed-role/*acm-renewal-distributor/*\") }"
    }
    ram-share-change = {
      description = "RAM resource share modified outside the pipeline (could widen who can issue)"
      pattern     = "{ ($.eventSource = \"ram.amazonaws.com\") && (($.eventName = \"AssociateResourceShare\") || ($.eventName = \"DisassociateResourceShare\") || ($.eventName = \"UpdateResourceShare\")) && ${local.pipeline_exclusion} }"
    }
    logging-tamper = {
      description = "CloudTrail stopped, deleted or modified"
      pattern     = "{ ($.eventSource = \"cloudtrail.amazonaws.com\") && (($.eventName = \"StopLogging\") || ($.eventName = \"DeleteTrail\") || ($.eventName = \"UpdateTrail\") || ($.eventName = \"PutEventSelectors\")) }"
    }
    kms-key-disable = {
      description = "KMS key disabled or scheduled for deletion"
      pattern     = "{ ($.eventSource = \"kms.amazonaws.com\") && (($.eventName = \"DisableKey\") || ($.eventName = \"ScheduleKeyDeletion\")) }"
    }
    console-login-no-mfa = {
      description = "Console login without MFA in the PKI account (PCI DSS 8.4)"
      pattern     = "{ ($.eventName = \"ConsoleLogin\") && ($.additionalEventData.MFAUsed != \"Yes\") && ($.responseElements.ConsoleLogin = \"Success\") }"
    }
  }
}

###############################################################################
# KMS
###############################################################################
data "aws_iam_policy_document" "kms" {
  #checkov:skip=CKV_AWS_109:KMS key policy: Resource must be * (it refers to the key itself)
  #checkov:skip=CKV_AWS_111:KMS key policy: Resource must be * (it refers to the key itself)
  #checkov:skip=CKV_AWS_356:KMS key policy: Resource must be * (it refers to the key itself)
  statement {
    sid       = "AccountAdmin"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:${local.partition}:iam::${local.account_id}:root"]
    }
  }

  statement {
    sid       = "CloudTrailEncrypt"
    actions   = ["kms:GenerateDataKey*"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:cloudtrail:arn"
      values   = ["arn:${local.partition}:cloudtrail:*:${local.account_id}:trail/*"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }

  statement {
    sid       = "CloudTrailDescribe"
    actions   = ["kms:DescribeKey"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }

  statement {
    sid       = "S3NotificationsToEncryptedSNS"
    actions   = ["kms:GenerateDataKey*", "kms:Decrypt"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["s3.amazonaws.com", "sns.amazonaws.com", "cloudwatch.amazonaws.com"]
    }
  }

  statement {
    sid       = "CloudWatchLogs"
    actions   = ["kms:Encrypt*", "kms:Decrypt*", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:Describe*"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["logs.${local.region}.amazonaws.com"]
    }
  }
}

resource "aws_kms_key" "trail" {
  description             = "PKI audit trail encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.kms.json
  tags                    = local.tags
}

resource "aws_kms_alias" "trail" {
  name          = "alias/${var.trail_name}"
  target_key_id = aws_kms_key.trail.key_id
}

###############################################################################
# S3 bucket for CloudTrail
###############################################################################
resource "aws_s3_bucket" "trail" {
  #checkov:skip=CKV_AWS_18:Access logging is configured through var.access_log_bucket (aws_s3_bucket_logging.trail)
  bucket              = var.bucket_name
  object_lock_enabled = var.object_lock.enabled
  force_destroy       = false
  tags                = local.tags
}

resource "aws_s3_bucket_public_access_block" "trail" {
  bucket                  = aws_s3_bucket.trail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "trail" {
  bucket = aws_s3_bucket.trail.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "trail" {
  bucket = aws_s3_bucket.trail.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.trail.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_logging" "trail" {
  count         = var.access_log_bucket != null ? 1 : 0
  bucket        = aws_s3_bucket.trail.id
  target_bucket = var.access_log_bucket
  target_prefix = "s3/${var.bucket_name}/"
}

resource "aws_s3_bucket_object_lock_configuration" "trail" {
  count  = var.object_lock.enabled ? 1 : 0
  bucket = aws_s3_bucket.trail.id

  rule {
    default_retention {
      mode = var.object_lock.mode
      days = var.object_lock.days
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id

  rule {
    id     = "retention"
    status = "Enabled"
    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }

    transition {
      days          = 90
      storage_class = "GLACIER_IR"
    }

    expiration {
      days = var.retention_days
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }
}

data "aws_iam_policy_document" "trail_bucket" {
  statement {
    sid       = "CloudTrailAclCheck"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.trail.arn]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }

  statement {
    sid       = "CloudTrailWrite"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.trail.arn}/AWSLogs/*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }

  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.trail.arn, "${aws_s3_bucket.trail.arn}/*"]
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

  statement {
    sid       = "DenyLogDeletion"
    effect    = "Deny"
    actions   = ["s3:DeleteObject", "s3:DeleteObjectVersion"]
    resources = [aws_s3_bucket.trail.arn, "${aws_s3_bucket.trail.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "StringNotLike"
      variable = "aws:PrincipalArn"
      values   = var.log_admin_role_arns
    }
  }
}

resource "aws_s3_bucket_policy" "trail" {
  bucket = aws_s3_bucket.trail.id
  policy = data.aws_iam_policy_document.trail_bucket.json
}

###############################################################################
# CloudWatch Logs delivery
###############################################################################
resource "aws_cloudwatch_log_group" "trail" {
  name              = "/aws/cloudtrail/${var.trail_name}"
  retention_in_days = var.cloudwatch_retention_days
  kms_key_id        = aws_kms_key.trail.arn
  tags              = local.tags
}

data "aws_iam_policy_document" "trail_logs_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "trail_logs" {
  name               = "${var.trail_name}-cloudwatch"
  assume_role_policy = data.aws_iam_policy_document.trail_logs_assume.json
  tags               = local.tags
}

resource "aws_iam_role_policy" "trail_logs" {
  name = "deliver-to-cloudwatch"
  role = aws_iam_role.trail_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = "${aws_cloudwatch_log_group.trail.arn}:*"
    }]
  })
}

###############################################################################
# The trail
###############################################################################
resource "aws_cloudtrail" "this" {
  #checkov:skip=CKV_AWS_252:New-file notifications are sent by S3 event notifications (Splunk SQS feed), not by the trail SNS option
  name                          = var.trail_name
  s3_bucket_name                = aws_s3_bucket.trail.id
  kms_key_id                    = aws_kms_key.trail.arn
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true # SHA-256 digest files: proves logs were not altered
  is_organization_trail         = var.is_organization_trail

  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.trail.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.trail_logs.arn

  tags = local.tags

  depends_on = [aws_s3_bucket_policy.trail, aws_iam_role_policy.trail_logs]
}

###############################################################################
# Tripwires: metric filters + alarms
###############################################################################
resource "aws_cloudwatch_log_metric_filter" "tripwire" {
  for_each = local.tripwires

  name           = "pki-${each.key}"
  log_group_name = aws_cloudwatch_log_group.trail.name
  pattern        = each.value.pattern

  metric_transformation {
    name          = "pki-${each.key}"
    namespace     = "PKI/Security"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "tripwire" {
  for_each = local.tripwires

  alarm_name          = "pki-security-${each.key}"
  alarm_description   = "${each.value.description}. Investigate in Splunk (index=aws sourcetype=aws:cloudtrail). Runbook: docs/runbooks/security-tripwire.md"
  namespace           = "PKI/Security"
  metric_name         = "pki-${each.key}"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [var.alerts_topic_arn]
  tags                = local.tags

  depends_on = [aws_cloudwatch_log_metric_filter.tripwire]
}

###############################################################################
# Splunk feed: S3 -> SNS -> SQS (Splunk Add-on for AWS, SQS-based S3 input)
###############################################################################
resource "aws_sns_topic" "trail_files" {
  count             = var.splunk.enabled ? 1 : 0
  name              = "${var.trail_name}-new-files"
  kms_master_key_id = aws_kms_key.trail.arn
  tags              = local.tags
}

resource "aws_sns_topic_policy" "trail_files" {
  count = var.splunk.enabled ? 1 : 0
  arn   = aws_sns_topic.trail_files[0].arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowS3Publish"
      Effect    = "Allow"
      Principal = { Service = "s3.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.trail_files[0].arn
      Condition = {
        ArnLike      = { "aws:SourceArn" = aws_s3_bucket.trail.arn }
        StringEquals = { "aws:SourceAccount" = local.account_id }
      }
    }]
  })
}

resource "aws_s3_bucket_notification" "trail_files" {
  count  = var.splunk.enabled ? 1 : 0
  bucket = aws_s3_bucket.trail.id

  topic {
    topic_arn     = aws_sns_topic.trail_files[0].arn
    events        = ["s3:ObjectCreated:*"]
    filter_prefix = "AWSLogs/"
    filter_suffix = ".json.gz"
  }

  depends_on = [aws_sns_topic_policy.trail_files]
}

resource "aws_sqs_queue" "splunk_dlq" {
  count                     = var.splunk.enabled ? 1 : 0
  name                      = "${var.trail_name}-splunk-dlq"
  message_retention_seconds = 1209600
  sqs_managed_sse_enabled   = true
  tags                      = local.tags
}

resource "aws_sqs_queue" "splunk" {
  count                      = var.splunk.enabled ? 1 : 0
  name                       = "${var.trail_name}-splunk"
  visibility_timeout_seconds = 300 # Splunk add-on recommendation
  message_retention_seconds  = 1209600
  sqs_managed_sse_enabled    = true
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.splunk_dlq[0].arn
    maxReceiveCount     = 5
  })
  tags = local.tags
}

resource "aws_sqs_queue_policy" "splunk" {
  count     = var.splunk.enabled ? 1 : 0
  queue_url = aws_sqs_queue.splunk[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowSNS"
      Effect    = "Allow"
      Principal = { Service = "sns.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.splunk[0].arn
      Condition = { ArnEquals = { "aws:SourceArn" = aws_sns_topic.trail_files[0].arn } }
    }]
  })
}

resource "aws_sns_topic_subscription" "splunk" {
  count     = var.splunk.enabled ? 1 : 0
  topic_arn = aws_sns_topic.trail_files[0].arn
  protocol  = "sqs"
  endpoint  = aws_sqs_queue.splunk[0].arn
}

data "aws_iam_policy_document" "splunk_assume" {
  count = var.splunk.enabled ? 1 : 0
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = [var.splunk.reader_principal_arn]
    }
    condition {
      test     = "StringEquals"
      variable = "sts:ExternalId"
      values   = [var.splunk.external_id]
    }
  }
}

resource "aws_iam_role" "splunk" {
  count                = var.splunk.enabled ? 1 : 0
  name                 = "${var.trail_name}-splunk-reader"
  assume_role_policy   = data.aws_iam_policy_document.splunk_assume[0].json
  max_session_duration = 3600
  tags                 = local.tags
}

resource "aws_iam_role_policy" "splunk" {
  count = var.splunk.enabled ? 1 : 0
  name  = "read-cloudtrail-via-sqs"
  role  = aws_iam_role.splunk[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes", "sqs:GetQueueUrl", "sqs:ChangeMessageVisibility"]
        Resource = aws_sqs_queue.splunk[0].arn
      },
      {
        Effect   = "Allow"
        Action   = ["sqs:ListQueues"]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = "${aws_s3_bucket.trail.arn}/AWSLogs/*"
      },
      {
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = aws_kms_key.trail.arn
      }
    ]
  })
}
