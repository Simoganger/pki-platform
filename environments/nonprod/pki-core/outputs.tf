# These outputs are consumed by other workspaces through the tfe_outputs data
# source (observability, workload accounts). They contain no secrets.

output "root_ca_arn" {
  description = "Root CA ARN."
  value       = module.root_ca.arn
}

output "root_ca_certificate_pem" {
  description = "Root certificate to distribute to trust stores."
  value       = module.root_ca.certificate_pem
}

output "issuing_ca_arns" {
  description = "Issuing CA ARNs by name."
  value       = { for k, ca in module.issuing_ca : k => ca.arn }
}

output "crl_urls" {
  description = "Every CRL URL published by this hierarchy, keyed by CA name."
  value = merge(
    { for k, ca in module.issuing_ca : k => ca.crl_url },
    { root-g1 = "http://${module.crl.cdp_hostname}/crl/${module.root_ca.id}.crl" },
  )
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

output "renewal_distributor_function" {
  description = "Lambda redistributing renewed certificates."
  value       = module.renewal_distributor.lambda_function_name
}

output "cert_secrets_kms_key_arn" {
  description = "KMS key of certificate secrets (workload roles need kms:Decrypt)."
  value       = module.renewal_distributor.secrets_kms_key_arn
}
