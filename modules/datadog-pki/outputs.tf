output "dashboard_url" {
  description = "URL path of the PKI dashboard."
  value       = datadog_dashboard_json.pki.url
}

output "monitor_ids" {
  description = "IDs of the monitors created."
  value = compact([
    datadog_monitor.acm_days_to_expiry.id,
    datadog_monitor.acm_renewal_action_required.id,
    datadog_monitor.crl_freshness.id,
    datadog_monitor.pca_sensitive_calls.id,
    try(datadog_monitor.hsm_snmp[0].id, ""),
  ])
}
