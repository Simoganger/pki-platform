###############################################################################
# Module: pki-monitoring
#
# Native AWS observability for the PKI, designed to feed Datadog and Splunk:
#
#   1. SNS topic "pki-alerts" (KMS-encrypted)      -> email / PagerDuty / Datadog
#   2. EventBridge rules on ACM + AWS Private CA events
#        -> SNS (actionable ones) and -> CloudWatch Logs /aws/events/pki
#           (ALL of them; the log group is streamed to Splunk by module
#            splunk-firehose and/or collected by the Datadog Forwarder)
#   3. CRL freshness checker (Lambda, every 15 min): downloads each CRL, reads
#      its nextUpdate field and publishes PKI/CRL metrics. An expired CRL makes
#      hard-fail clients reject EVERY certificate of that CA - this is the most
#      under-monitored failure mode in PKI.
#   4. CloudWatch alarms on those metrics.
###############################################################################

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
  region     = data.aws_region.current.region
  tags       = merge(var.tags, { "pki:component" = "monitoring" })
}

###############################################################################
# KMS + SNS
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
    sid       = "AllowAWSServicesToPublishEncrypted"
    actions   = ["kms:GenerateDataKey*", "kms:Decrypt"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com", "cloudwatch.amazonaws.com"]
    }
  }

  statement {
    sid       = "AllowCloudWatchLogs"
    actions   = ["kms:Encrypt*", "kms:Decrypt*", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:Describe*"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["logs.${local.region}.amazonaws.com"]
    }
    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["arn:${local.partition}:logs:${local.region}:${local.account_id}:log-group:*"]
    }
  }
}

resource "aws_kms_key" "monitoring" {
  description             = "PKI monitoring - SNS and log encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.kms.json
  tags                    = local.tags
}

resource "aws_kms_alias" "monitoring" {
  name          = "alias/${var.name_prefix}-monitoring"
  target_key_id = aws_kms_key.monitoring.key_id
}

resource "aws_sns_topic" "alerts" {
  name              = "${var.name_prefix}-alerts"
  kms_master_key_id = aws_kms_key.monitoring.arn
  tags              = local.tags
}

data "aws_iam_policy_document" "sns" {
  statement {
    sid       = "AllowEventBridgeAndCloudWatch"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com", "cloudwatch.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }

  statement {
    sid       = "AllowAccountPublishers"
    actions   = ["sns:Publish", "sns:Subscribe", "sns:GetTopicAttributes"]
    resources = [aws_sns_topic.alerts.arn]
    principals {
      type        = "AWS"
      identifiers = ["arn:${local.partition}:iam::${local.account_id}:root"]
    }
  }
}

resource "aws_sns_topic_policy" "alerts" {
  arn    = aws_sns_topic.alerts.arn
  policy = data.aws_iam_policy_document.sns.json
}

resource "aws_sns_topic_subscription" "email" {
  for_each  = toset(var.alert_emails)
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = each.value
}

resource "aws_sns_topic_subscription" "https" {
  # e.g. Datadog SNS webhook or PagerDuty Events API v2 integration URL
  for_each               = toset(var.alert_https_endpoints)
  topic_arn              = aws_sns_topic.alerts.arn
  protocol               = "https"
  endpoint               = each.value
  endpoint_auto_confirms = true
}

###############################################################################
# EventBridge -> CloudWatch Logs (everything, for SIEM)
###############################################################################
resource "aws_cloudwatch_log_group" "events" {
  name              = "/aws/events/${var.name_prefix}"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.monitoring.arn
  tags              = local.tags
}

data "aws_iam_policy_document" "events_to_logs" {
  statement {
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.events.arn}:*"]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com", "delivery.logs.amazonaws.com"]
    }
  }
}

resource "aws_cloudwatch_log_resource_policy" "events" {
  policy_name     = "${var.name_prefix}-eventbridge-to-logs"
  policy_document = data.aws_iam_policy_document.events_to_logs.json
}

resource "aws_cloudwatch_event_rule" "all_pki_events" {
  name        = "${var.name_prefix}-all-pki-events"
  description = "Every ACM and AWS Private CA event, archived for Splunk / Datadog"
  event_pattern = jsonencode({
    source = ["aws.acm", "aws.acm-pca"]
  })
  tags = local.tags
}

resource "aws_cloudwatch_event_target" "all_to_logs" {
  rule = aws_cloudwatch_event_rule.all_pki_events.name
  arn  = aws_cloudwatch_log_group.events.arn
}

###############################################################################
# EventBridge -> SNS (actionable events only)
###############################################################################
resource "aws_cloudwatch_event_rule" "acm_actionable" {
  name        = "${var.name_prefix}-acm-actionable"
  description = "ACM certificates approaching expiry, expired, or whose renewal needs action"
  event_pattern = jsonencode({
    source = ["aws.acm"]
    detail-type = [
      "ACM Certificate Approaching Expiration",
      "ACM Certificate Expired",
      "ACM Certificate Renewal Action Required",
    ]
  })
  tags = local.tags
}

resource "aws_cloudwatch_event_target" "acm_to_sns" {
  rule = aws_cloudwatch_event_rule.acm_actionable.name
  arn  = aws_sns_topic.alerts.arn
}

resource "aws_cloudwatch_event_rule" "pca_failures" {
  name        = "${var.name_prefix}-pca-failures"
  description = "AWS Private CA operations that failed (CRL generation, issuance, revocation, audit report)"
  event_pattern = jsonencode({
    source = ["aws.acm-pca"]
    detail = {
      result = ["failure"]
    }
  })
  tags = local.tags
}

resource "aws_cloudwatch_event_target" "pca_to_sns" {
  rule = aws_cloudwatch_event_rule.pca_failures.name
  arn  = aws_sns_topic.alerts.arn
}

resource "aws_cloudwatch_event_rule" "pca_revocations" {
  name        = "${var.name_prefix}-pca-revocations"
  description = "Every certificate revocation is notified (security relevant)"
  event_pattern = jsonencode({
    source      = ["aws.acm-pca"]
    detail-type = ["ACM Private CA Certificate Revocation"]
  })
  tags = local.tags
}

resource "aws_cloudwatch_event_target" "revocations_to_sns" {
  rule = aws_cloudwatch_event_rule.pca_revocations.name
  arn  = aws_sns_topic.alerts.arn
}

###############################################################################
# CRL freshness checker
###############################################################################
data "archive_file" "crl_checker" {
  type        = "zip"
  source_dir  = var.crl_checker_source_dir
  output_path = "${path.module}/.build/crl_freshness_checker.zip"
}

resource "aws_cloudwatch_log_group" "crl_checker" {
  name              = "/aws/lambda/${var.name_prefix}-crl-freshness-checker"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.monitoring.arn
  tags              = local.tags
}

data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "crl_checker" {
  name               = "${var.name_prefix}-crl-freshness-checker"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
  tags               = local.tags
}

data "aws_iam_policy_document" "crl_checker" {
  statement {
    actions   = ["cloudwatch:PutMetricData"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "cloudwatch:namespace"
      values   = ["PKI/CRL"]
    }
  }
  statement {
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.crl_checker.arn}:*"]
  }
}

resource "aws_iam_role_policy" "crl_checker" {
  name   = "crl-freshness-checker"
  role   = aws_iam_role.crl_checker.id
  policy = data.aws_iam_policy_document.crl_checker.json
}

resource "aws_lambda_function" "crl_checker" {
  #checkov:skip=CKV_AWS_116:Scheduled every 15 min; a failed run is re-done by the next schedule and missing metrics raise the alarm
  #checkov:skip=CKV_AWS_173:Environment variables hold only public CRL URLs
  function_name    = "${var.name_prefix}-crl-freshness-checker"
  description      = "Checks that every published CRL is reachable and fresh"
  role             = aws_iam_role.crl_checker.arn
  runtime          = "python3.13"
  handler          = "handler.lambda_handler"
  filename         = data.archive_file.crl_checker.output_path
  source_code_hash = data.archive_file.crl_checker.output_base64sha256
  timeout          = 60
  memory_size      = 128

  reserved_concurrent_executions = 1

  tracing_config {
    mode = "Active"
  }

  environment {
    variables = {
      CRL_URLS         = join(",", values(var.crl_urls))
      METRIC_NAMESPACE = "PKI/CRL"
    }
  }

  depends_on = [aws_cloudwatch_log_group.crl_checker, aws_iam_role_policy.crl_checker]
  tags       = local.tags
}

resource "aws_cloudwatch_event_rule" "crl_schedule" {
  name                = "${var.name_prefix}-crl-freshness-schedule"
  schedule_expression = "rate(15 minutes)"
  tags                = local.tags
}

resource "aws_cloudwatch_event_target" "crl_schedule" {
  rule = aws_cloudwatch_event_rule.crl_schedule.name
  arn  = aws_lambda_function.crl_checker.arn
}

resource "aws_lambda_permission" "crl_schedule" {
  statement_id  = "AllowSchedule"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.crl_checker.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.crl_schedule.arn
}

resource "aws_cloudwatch_metric_alarm" "crl_stale" {
  for_each = var.crl_urls

  alarm_name          = "${var.name_prefix}-crl-stale-${each.key}"
  alarm_description   = "CRL ${each.value} expires in less than ${var.crl_min_hours_remaining}h (nextUpdate). Runbook: docs/runbooks/crl-expired.md"
  namespace           = "PKI/CRL"
  metric_name         = "HoursUntilNextUpdate"
  dimensions          = { CrlUrl = each.value }
  statistic           = "Minimum"
  period              = 900
  evaluation_periods  = 1
  threshold           = var.crl_min_hours_remaining
  comparison_operator = "LessThanThreshold"
  treat_missing_data  = "breaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
  tags                = local.tags
}

resource "aws_cloudwatch_metric_alarm" "crl_unreachable" {
  for_each = var.crl_urls

  alarm_name          = "${var.name_prefix}-crl-unreachable-${each.key}"
  alarm_description   = "CRL ${each.value} could not be downloaded or parsed twice in a row. Runbook: docs/runbooks/crl-expired.md"
  namespace           = "PKI/CRL"
  metric_name         = "FetchSuccess"
  dimensions          = { CrlUrl = each.value }
  statistic           = "Maximum"
  period              = 900
  evaluation_periods  = 2
  threshold           = 1
  comparison_operator = "LessThanThreshold"
  treat_missing_data  = "breaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
  tags                = local.tags
}
