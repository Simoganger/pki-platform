output "splunk_sqs_queue_url" {
  description = "Configure this queue in the Splunk Add-on for AWS (SQS-based S3 input, sourcetype aws:cloudtrail)."
  value       = module.audit_logging.splunk_sqs_queue_url
}

output "splunk_reader_role_arn" {
  description = "IAM role for the Splunk add-on (use with the external ID)."
  value       = module.audit_logging.splunk_reader_role_arn
}

output "datadog_dashboard_url" {
  description = "PKI dashboard in Datadog."
  value       = module.datadog.dashboard_url
}

output "cloudtrail_arn" {
  description = "Audit trail."
  value       = module.audit_logging.trail_arn
}
