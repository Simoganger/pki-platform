###############################################################################
# Module: splunk-firehose
#
# Streams PKI CloudWatch log groups to Splunk HTTP Event Collector (HEC)
# through Amazon Data Firehose, in near real time:
#
#   /aws/events/pki-*            (every ACM / Private CA event)   \
#   /aws/lambda/*crl-checker*    (CRL freshness checks)            >--> subscription filter
#   /aws/lambda/*distributor*    (certificate redistribution)     /        |
#                                                                          v
#              Firehose (decompress + extract CW Logs messages) --> Splunk HEC
#                                 |  failed events only
#                                 v
#                              S3 backup bucket (replay)
#
# CloudTrail itself goes to Splunk through the SQS-based S3 input
# (module pki-audit-logging), which is the pattern Splunk recommends for
# high-volume AWS logs.
#
# The HEC token is NEVER passed to Terraform: Firehose reads it from Secrets
# Manager at runtime (secret JSON: {"hec_token":"<token>"}).
###############################################################################

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
  region     = data.aws_region.current.region
  tags       = merge(var.tags, { "pki:component" = "splunk-integration" })
}

resource "aws_s3_bucket" "backup" {
  #checkov:skip=CKV_AWS_18:Short-lived replay buffer for failed events; access is audited by CloudTrail data events if enabled
  bucket = var.backup_bucket_name
  tags   = local.tags
}

resource "aws_s3_bucket_versioning" "backup" {
  bucket = aws_s3_bucket.backup.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "backup" {
  bucket                  = aws_s3_bucket.backup.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "backup" {
  bucket = aws_s3_bucket.backup.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "backup" {
  bucket = aws_s3_bucket.backup.id
  rule {
    id     = "expire"
    status = "Enabled"
    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
    expiration {
      days = 90
    }
  }
}

resource "aws_cloudwatch_log_group" "firehose" {
  #checkov:skip=CKV_AWS_158:Firehose delivery-error logs contain no event payloads
  name              = "/aws/kinesisfirehose/${var.name_prefix}-splunk"
  retention_in_days = 365
  tags              = local.tags
}

resource "aws_cloudwatch_log_stream" "firehose" {
  name           = "DestinationDelivery"
  log_group_name = aws_cloudwatch_log_group.firehose.name
}

###############################################################################
# Firehose role
###############################################################################
data "aws_iam_policy_document" "firehose_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["firehose.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "sts:ExternalId"
      values   = [local.account_id]
    }
  }
}

resource "aws_iam_role" "firehose" {
  name               = "${var.name_prefix}-splunk-firehose"
  assume_role_policy = data.aws_iam_policy_document.firehose_assume.json
  tags               = local.tags
}

resource "aws_iam_role_policy" "firehose" {
  name = "firehose-to-splunk"
  role = aws_iam_role.firehose.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:AbortMultipartUpload", "s3:GetBucketLocation", "s3:GetObject", "s3:ListBucket", "s3:ListBucketMultipartUploads", "s3:PutObject"]
        Resource = [aws_s3_bucket.backup.arn, "${aws_s3_bucket.backup.arn}/*"]
      },
      {
        Effect   = "Allow"
        Action   = ["logs:PutLogEvents"]
        Resource = "${aws_cloudwatch_log_group.firehose.arn}:*"
      },
      {
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = var.hec_token_secret_arn
      },
      {
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = "*"
        Condition = {
          StringEquals = { "kms:ViaService" = "secretsmanager.${local.region}.amazonaws.com" }
        }
      }
    ]
  })
}

###############################################################################
# Delivery stream
###############################################################################
resource "aws_kinesis_firehose_delivery_stream" "splunk" {
  #checkov:skip=CKV_AWS_241:Records are PKI operational logs (no key material); AWS-owned key avoids a cross-service CMK dependency. Switch key_type to CUSTOMER_MANAGED_CMK if your policy requires it.
  name        = "${var.name_prefix}-pki-to-splunk"
  destination = "splunk"

  server_side_encryption {
    enabled  = true
    key_type = "AWS_OWNED_CMK"
  }

  splunk_configuration {
    hec_endpoint               = var.hec_endpoint
    hec_endpoint_type          = "Event"
    hec_acknowledgment_timeout = 600
    retry_duration             = 3600
    s3_backup_mode             = "FailedEventsOnly"

    secrets_manager_configuration {
      enabled    = true
      secret_arn = var.hec_token_secret_arn
      role_arn   = aws_iam_role.firehose.arn
    }

    s3_configuration {
      role_arn           = aws_iam_role.firehose.arn
      bucket_arn         = aws_s3_bucket.backup.arn
      prefix             = "failed/"
      compression_format = "GZIP"
    }

    # CloudWatch Logs records arrive gzipped and wrapped in an envelope:
    # Firehose's built-in processors unzip them and extract each log message.
    processing_configuration {
      enabled = true

      processors {
        type = "Decompression"
        parameters {
          parameter_name  = "CompressionFormat"
          parameter_value = "GZIP"
        }
      }

      processors {
        type = "CloudWatchLogProcessing"
        parameters {
          parameter_name  = "DataMessageExtraction"
          parameter_value = "true"
        }
      }
    }

    cloudwatch_logging_options {
      enabled         = true
      log_group_name  = aws_cloudwatch_log_group.firehose.name
      log_stream_name = aws_cloudwatch_log_stream.firehose.name
    }
  }

  tags = local.tags
}

###############################################################################
# CloudWatch Logs subscriptions
###############################################################################
data "aws_iam_policy_document" "logs_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["logs.${local.region}.amazonaws.com"]
    }
    condition {
      test     = "StringLike"
      variable = "aws:SourceArn"
      values   = ["arn:${local.partition}:logs:${local.region}:${local.account_id}:*"]
    }
  }
}

resource "aws_iam_role" "logs_to_firehose" {
  name               = "${var.name_prefix}-logs-to-splunk-firehose"
  assume_role_policy = data.aws_iam_policy_document.logs_assume.json
  tags               = local.tags
}

resource "aws_iam_role_policy" "logs_to_firehose" {
  name = "put-records"
  role = aws_iam_role.logs_to_firehose.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["firehose:PutRecord", "firehose:PutRecordBatch"]
      Resource = aws_kinesis_firehose_delivery_stream.splunk.arn
    }]
  })
}

resource "aws_cloudwatch_log_subscription_filter" "splunk" {
  for_each = toset(var.log_group_names)

  name            = "to-splunk"
  log_group_name  = each.value
  filter_pattern  = "" # everything
  destination_arn = aws_kinesis_firehose_delivery_stream.splunk.arn
  role_arn        = aws_iam_role.logs_to_firehose.arn

  depends_on = [aws_iam_role_policy.logs_to_firehose]
}
