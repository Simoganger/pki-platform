output "issuing_ca_arns" {
  description = "Issuing CA ARNs by name."
  value       = { for k, ca in module.issuing_ca : k => ca.arn }
}

output "issuing_ca_status" {
  description = "Lifecycle state of each issuing CA (PENDING_CERTIFICATE until the ceremony file is committed)."
  value       = { for k, ca in module.issuing_ca : k => ca.status_hint }
}

output "issuing_ca_csrs" {
  description = "CSRs to bring to the key ceremony (only for CAs not yet signed)."
  value       = { for k, ca in module.issuing_ca : k => ca.csr_pem if !local.ca_is_signed[k] }
}

output "crl_urls" {
  description = "CRL URLs of the ACTIVE issuing CAs."
  value       = { for k, ca in module.issuing_ca : k => ca.crl_url if local.ca_is_signed[k] }
}

output "alerts_topic_arn" {
  description = "SNS topic for PKI alerts."
  value       = module.monitoring.alerts_topic_arn
}

output "monitoring_log_group_names" {
  description = "Log groups to stream to Splunk / Datadog."
  value = [
    module.monitoring.events_log_group_name,
    module.monitoring.crl_checker_log_group_name,
    "/aws/lambda/${module.renewal_distributor.lambda_function_name}",
  ]
}

output "cert_secrets_kms_key_arn" {
  description = "KMS key of certificate secrets."
  value       = module.renewal_distributor.secrets_kms_key_arn
}
