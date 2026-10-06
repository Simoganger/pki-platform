###############################################################################
# Module: acm-renewal-distributor
#
# Closes the auto-renewal loop for workloads that are NOT integrated with ACM
# (EC2 with nginx/Apache/IIS, containers, on-prem servers reached via SSM).
#
#   ACM renews the cert  --> EventBridge "ACM Certificate Available"
#        --> Lambda: exports cert + key from ACM, stores them in Secrets Manager
#            (KMS-encrypted, readable only by the workload role named in the
#            certificate tag pki:reader-role)
#        --> optional SSM Run Command on instances tagged pki:cert=<value>
#            runs /usr/local/bin/pki-cert-sync.sh to install + reload
#        --> SNS notification + structured log (Splunk / Datadog)
#
# Only certificates tagged pki:distribute=secretsmanager are processed (set by
# module acm-private-certificate when `distribution` is configured).
#
# SECURITY NOTES
#   - Exporting a private key is a sensitive operation: acm:ExportCertificate
#     is granted ONLY to this Lambda role, and only on certificates carrying the
#     opt-in tag (ABAC condition).
#   - The key never touches Terraform state or GitHub; it lives in ACM and in
#     one KMS-encrypted secret.
#   - Prefer ACM-integrated services (ALB, API GW, CloudFront) whenever possible:
#     the key is then never exported at all.
###############################################################################

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
  region     = data.aws_region.current.region
  tags       = merge(var.tags, { "pki:component" = "renewal-distributor" })
}

###############################################################################
# KMS key for the certificate secrets
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
    sid       = "SecretsManagerUseForCertSecrets"
    actions   = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey*", "kms:DescribeKey"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["secretsmanager.${local.region}.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "kms:CallerAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_kms_key" "secrets" {
  description             = "PKI - encryption of exported certificate secrets"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.kms.json
  tags                    = local.tags
}

resource "aws_kms_alias" "secrets" {
  name          = "alias/${var.name_prefix}-cert-secrets"
  target_key_id = aws_kms_key.secrets.key_id
}

###############################################################################
# Lambda
###############################################################################
data "archive_file" "lambda" {
  type        = "zip"
  source_dir  = var.lambda_source_dir
  output_path = "${path.module}/.build/acm_renewal_distributor.zip"
}

resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/${var.name_prefix}-acm-renewal-distributor"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.logs_kms_key_arn
  tags              = local.tags
}

resource "aws_sqs_queue" "dlq" {
  name                      = "${var.name_prefix}-acm-renewal-distributor-dlq"
  message_retention_seconds = 1209600
  sqs_managed_sse_enabled   = true
  tags                      = local.tags
}

data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "lambda" {
  name               = "${var.name_prefix}-acm-renewal-distributor"
  assume_role_policy = data.aws_iam_policy_document.assume.json
  tags               = local.tags
}

data "aws_iam_policy_document" "lambda" {
  statement {
    sid       = "ReadCertificateMetadata"
    actions   = ["acm:DescribeCertificate", "acm:ListTagsForCertificate"]
    resources = ["arn:${local.partition}:acm:${local.region}:${local.account_id}:certificate/*"]
  }

  statement {
    sid       = "ExportOnlyOptedInCertificates"
    actions   = ["acm:ExportCertificate"]
    resources = ["arn:${local.partition}:acm:${local.region}:${local.account_id}:certificate/*"]
    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/pki:distribute"
      values   = ["secretsmanager"]
    }
  }

  statement {
    sid = "ManageCertificateSecrets"
    actions = [
      "secretsmanager:CreateSecret",
      "secretsmanager:PutSecretValue",
      "secretsmanager:DescribeSecret",
      "secretsmanager:PutResourcePolicy",
      "secretsmanager:TagResource",
    ]
    resources = ["arn:${local.partition}:secretsmanager:${local.region}:${local.account_id}:secret:${var.secret_name_prefix}*"]
  }

  statement {
    sid       = "UseSecretsKey"
    actions   = ["kms:GenerateDataKey", "kms:Encrypt", "kms:Decrypt", "kms:DescribeKey"]
    resources = [aws_kms_key.secrets.arn]
  }

  statement {
    sid       = "NotifyOwners"
    actions   = ["sns:Publish"]
    resources = [var.notification_topic_arn]
  }

  statement {
    sid       = "ReloadOnTaggedInstances"
    actions   = ["ssm:SendCommand"]
    resources = [aws_ssm_document.reload.arn]
  }

  statement {
    sid       = "ReloadTargetInstances"
    actions   = ["ssm:SendCommand"]
    resources = ["arn:${local.partition}:ec2:${local.region}:${local.account_id}:instance/*"]
    condition {
      test     = "StringLike"
      variable = "ssm:resourceTag/pki:cert"
      values   = ["*"]
    }
  }

  statement {
    sid       = "Logs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.lambda.arn}:*"]
  }

  statement {
    sid       = "DeadLetter"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.dlq.arn]
  }
}

resource "aws_iam_role_policy" "lambda" {
  name   = "acm-renewal-distributor"
  role   = aws_iam_role.lambda.id
  policy = data.aws_iam_policy_document.lambda.json
}

resource "aws_lambda_function" "this" {
  #checkov:skip=CKV_AWS_173:Environment variables hold only names/ARNs, no secrets (encrypted at rest by AWS-managed key)
  function_name    = "${var.name_prefix}-acm-renewal-distributor"
  description      = "Redistributes renewed ACM certificates to Secrets Manager / SSM targets"
  role             = aws_iam_role.lambda.arn
  runtime          = "python3.13"
  architectures    = ["x86_64"] # must match the platform used to build the cryptography wheel
  handler          = "handler.lambda_handler"
  filename         = data.archive_file.lambda.output_path
  source_code_hash = data.archive_file.lambda.output_base64sha256
  timeout          = 60
  memory_size      = 256

  reserved_concurrent_executions = 5

  dead_letter_config {
    target_arn = aws_sqs_queue.dlq.arn
  }

  tracing_config {
    mode = "Active"
  }

  environment {
    variables = {
      SECRET_NAME_PREFIX     = var.secret_name_prefix
      SECRETS_KMS_KEY_ID     = aws_kms_key.secrets.arn
      NOTIFICATION_TOPIC_ARN = var.notification_topic_arn
      SSM_DOCUMENT_NAME      = aws_ssm_document.reload.name
      LOG_LEVEL              = "INFO"
    }
  }

  depends_on = [aws_cloudwatch_log_group.lambda, aws_iam_role_policy.lambda]
  tags       = local.tags
}

###############################################################################
# EventBridge: renewal / first issuance
###############################################################################
resource "aws_cloudwatch_event_rule" "available" {
  name        = "${var.name_prefix}-acm-certificate-available"
  description = "ACM issued or renewed a certificate"
  event_pattern = jsonencode({
    source      = ["aws.acm"]
    detail-type = ["ACM Certificate Available"]
  })
  tags = local.tags
}

resource "aws_cloudwatch_event_target" "lambda" {
  rule = aws_cloudwatch_event_rule.available.name
  arn  = aws_lambda_function.this.arn

  retry_policy {
    maximum_retry_attempts       = 10
    maximum_event_age_in_seconds = 86400
  }

  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
  }
}

resource "aws_lambda_permission" "events" {
  statement_id  = "AllowEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.this.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.available.arn
}

data "aws_iam_policy_document" "dlq" {
  statement {
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.dlq.arn]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_cloudwatch_event_rule.available.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "dlq" {
  queue_url = aws_sqs_queue.dlq.id
  policy    = data.aws_iam_policy_document.dlq.json
}

resource "aws_cloudwatch_metric_alarm" "dlq" {
  alarm_name          = "${var.name_prefix}-acm-renewal-distributor-dlq-not-empty"
  alarm_description   = "Renewed certificates could not be redistributed. Runbook: docs/runbooks/certificate-renewal-failure.md"
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateNumberOfMessagesVisible"
  statistic           = "Maximum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  dimensions          = { QueueName = aws_sqs_queue.dlq.name }
  alarm_actions       = [var.notification_topic_arn]
  tags                = local.tags
}

###############################################################################
# SSM document executed on the workload hosts
###############################################################################
resource "aws_ssm_document" "reload" {
  name            = "${var.name_prefix}-ReloadCertificate"
  document_type   = "Command"
  document_format = "YAML"
  content         = <<-YAML
    schemaVersion: "2.2"
    description: "PKI - fetch the renewed certificate from Secrets Manager and reload the service"
    parameters:
      SecretName:
        type: String
        description: Secrets Manager secret holding the certificate bundle
        allowedPattern: "^${var.secret_name_prefix}[A-Za-z0-9/_.-]+$"
    mainSteps:
      - action: aws:runShellScript
        name: syncCertificate
        precondition:
          StringEquals: [platformType, Linux]
        inputs:
          timeoutSeconds: "120"
          runCommand:
            - /usr/local/bin/pki-cert-sync.sh "{{ SecretName }}"
  YAML
  tags            = local.tags
}
