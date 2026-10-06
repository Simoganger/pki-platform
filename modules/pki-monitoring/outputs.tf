output "alerts_topic_arn" {
  description = "SNS topic for PKI alerts."
  value       = aws_sns_topic.alerts.arn
}

output "events_log_group_name" {
  description = "Log group receiving every ACM / PCA event (stream it to Splunk / Datadog)."
  value       = aws_cloudwatch_log_group.events.name
}

output "events_log_group_arn" {
  description = "ARN of the events log group."
  value       = aws_cloudwatch_log_group.events.arn
}

output "kms_key_arn" {
  description = "KMS key used by SNS and the log groups."
  value       = aws_kms_key.monitoring.arn
}

output "crl_checker_log_group_name" {
  description = "Log group of the CRL checker."
  value       = aws_cloudwatch_log_group.crl_checker.name
}
