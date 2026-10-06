###############################################################################
# Module: datadog-pki
#
# Datadog monitors, synthetic tests and a dashboard for the PKI.
#
# PREREQUISITES (usually owned by the observability team, not this repo):
#   - Datadog AWS integration on the PKI accounts with the "CertificateManager"
#     and "ACMPrivateCA" namespaces enabled, and custom CloudWatch namespaces
#     collected (PKI/CRL, PKI/Security).
#   - Datadog Forwarder (or Amazon Data Firehose) shipping CloudTrail and the
#     /aws/events/pki-* log groups to Datadog Logs.
#   - Datadog Agent with the SNMP integration on a relay host in the HSM
#     management network (observability/datadog-agent/conf.d/snmp.d/conf.yaml).
#   - A Synthetics PRIVATE location inside the network for endpoints using the
#     internal PKI (public locations neither reach nor trust them).
#
# METRIC NAMES: Datadog derives metric names from CloudWatch. The defaults
# below are what Datadog publishes for these namespaces at the time of writing;
# confirm them in Metrics Explorer and override the variables if needed.
###############################################################################

locals {
  notify   = join(" ", var.notify_handles)
  base_tag = ["team:pki", "env:${var.env}", "managed-by:terraform"]
  filter   = "env:${var.env}"
}

###############################################################################
# Certificates
###############################################################################
resource "datadog_monitor" "acm_days_to_expiry" {
  name     = "[PKI][${var.env}] ACM certificate expires soon - {{domainname.name}}"
  type     = "metric alert"
  priority = 2
  query    = "min(last_4h):min:${var.metric_acm_days_to_expiry}{${local.filter}} by {certificatearn,domainname} < ${var.cert_critical_days}"

  message = <<-EOT
    {{#is_warning}}Certificate **{{domainname.name}}** expires in {{value}} days. ACM should already have renewed it.{{/is_warning}}
    {{#is_alert}}Certificate **{{domainname.name}}** expires in {{value}} days - managed renewal FAILED.{{/is_alert}}

    ARN: {{certificatearn.name}}
    Runbook: ${var.runbook_base_url}/certificate-renewal-failure.md
    Common causes: CA disabled/expired, missing acm.amazonaws.com permission on the CA,
    DNS validation record deleted (public certs), certificate not in use (private certs
    are renewed only if exported or associated).

    ${local.notify}
  EOT

  monitor_thresholds {
    warning  = var.cert_warning_days
    critical = var.cert_critical_days
  }

  notify_no_data    = false
  renotify_interval = 720
  include_tags      = true
  tags              = concat(local.base_tag, ["pki:check:certificate-expiry"])
}

resource "datadog_monitor" "acm_renewal_action_required" {
  name     = "[PKI][${var.env}] ACM renewal requires action"
  type     = "log alert"
  priority = 2
  query    = "logs(\"source:aws service:events @detail-type:\\\"ACM Certificate Renewal Action Required\\\" env:${var.env}\").index(\"*\").rollup(\"count\").last(\"15m\") > 0"

  message = <<-EOT
    ACM could not renew a certificate automatically. Check the event detail for the
    certificate ARN and the failure reason.
    Runbook: ${var.runbook_base_url}/certificate-renewal-failure.md
    ${local.notify}
  EOT

  monitor_thresholds {
    critical = 0
  }

  tags = concat(local.base_tag, ["pki:check:renewal"])
}

###############################################################################
# CRL freshness (metrics published by the crl-freshness-checker Lambda)
###############################################################################
resource "datadog_monitor" "crl_freshness" {
  name     = "[PKI][${var.env}] CRL close to expiry - {{crlurl.name}}"
  type     = "metric alert"
  priority = 1
  query    = "min(last_30m):min:${var.metric_crl_hours_until_next_update}{${local.filter}} by {crlurl} < ${var.crl_critical_hours}"

  message = <<-EOT
    The CRL {{crlurl.name}} has only {{value}} hours before nextUpdate.
    When it expires, hard-fail clients will reject EVERY certificate of this CA.
    Runbook: ${var.runbook_base_url}/crl-expired.md
    ${local.notify}
  EOT

  monitor_thresholds {
    warning  = var.crl_warning_hours
    critical = var.crl_critical_hours
  }

  notify_no_data    = true
  no_data_timeframe = 60
  tags              = concat(local.base_tag, ["pki:check:crl"])
}

resource "datadog_synthetics_test" "crl_http" {
  for_each = var.crl_urls

  name      = "[PKI][${var.env}] CRL reachable - ${each.key}"
  type      = "api"
  subtype   = "http"
  status    = "live"
  locations = var.synthetics_locations
  message   = "CRL ${each.value} is not reachable. Runbook: ${var.runbook_base_url}/crl-expired.md ${local.notify}"
  tags      = concat(local.base_tag, ["pki:check:crl-http"])

  request_definition {
    method = "GET"
    url    = each.value
  }

  assertion {
    type     = "statusCode"
    operator = "is"
    target   = "200"
  }

  assertion {
    type     = "responseTime"
    operator = "lessThan"
    target   = "3000"
  }

  options_list {
    tick_every = 300
    retry {
      count    = 2
      interval = 30000
    }
    monitor_options {
      renotify_interval = 120
    }
  }
}

###############################################################################
# TLS endpoints (end-to-end view: what clients really see)
###############################################################################
resource "datadog_synthetics_test" "tls_endpoint" {
  for_each = { for e in var.tls_endpoints : "${e.host}:${e.port}" => e }

  name      = "[PKI][${var.env}] TLS certificate - ${each.key}"
  type      = "api"
  subtype   = "ssl"
  status    = "live"
  locations = coalescelist(each.value.locations, var.synthetics_locations)
  message   = "TLS certificate on ${each.key} is invalid, revoked or expires within ${var.cert_critical_days} days. ${local.notify}"
  tags      = concat(local.base_tag, ["pki:check:tls-endpoint"])

  request_definition {
    host = each.value.host
    port = tostring(each.value.port)
  }

  assertion {
    type     = "certificate"
    operator = "isInMoreThan"
    target   = tostring(var.cert_critical_days)
  }

  options_list {
    tick_every                   = 3600
    accept_self_signed           = false
    check_certificate_revocation = true
  }
}

###############################################################################
# Security: sensitive Private CA API calls seen in CloudTrail logs
###############################################################################
resource "datadog_monitor" "pca_sensitive_calls" {
  name     = "[PKI][${var.env}] Sensitive AWS Private CA API call - {{@evt.name}}"
  type     = "log alert"
  priority = 1
  query    = "logs(\"source:cloudtrail @eventSource:acm-pca.amazonaws.com @evt.name:(DeleteCertificateAuthority OR UpdateCertificateAuthority OR RestoreCertificateAuthority OR CreatePermission OR DeletePermission OR PutPolicy OR DeletePolicy OR ImportCertificateAuthorityCertificate) -@userIdentity.arn:*hcp-terraform-pki-apply*\").index(\"*\").rollup(\"count\").by(\"@evt.name\").last(\"5m\") > 0"

  message = <<-EOT
    A trust-changing or destructive AWS Private CA call was made OUTSIDE the
    HCP Terraform pipeline: {{@evt.name}}.
    Treat as a potential security incident until proven otherwise.
    Runbook: ${var.runbook_base_url}/security-tripwire.md
    ${local.notify} ${join(" ", var.security_notify_handles)}
  EOT

  monitor_thresholds {
    critical = 0
  }

  tags = concat(local.base_tag, ["pki:check:security"])
}

###############################################################################
# HSM availability (SNMPv3 polled by the Datadog Agent)
###############################################################################
resource "datadog_monitor" "hsm_snmp" {
  count = var.hsm_monitoring_enabled ? 1 : 0

  name     = "[PKI][${var.env}] HSM not answering SNMP - {{snmp_device.name}}"
  type     = "service check"
  priority = 1
  query    = "\"snmp.can_check\".over(\"device_namespace:${var.hsm_device_namespace}\").by(\"snmp_device\").last(3).count_by_status()"

  message = <<-EOT
    The HSM {{snmp_device.name}} has not answered SNMPv3 polling 3 times in a row.
    It may be down, unreachable from the monitoring relay, or the SNMPv3
    credentials may have been rotated without updating the agent.
    Runbook: ${var.runbook_base_url}/hsm-health.md
    ${local.notify}
  EOT

  monitor_thresholds {
    critical = 2
    warning  = 1
    ok       = 1
  }

  notify_no_data    = true
  no_data_timeframe = 30
  tags              = concat(local.base_tag, ["pki:check:hsm"])
}

###############################################################################
# Dashboard
###############################################################################
resource "datadog_dashboard_json" "pki" {
  dashboard = templatefile("${path.module}/dashboard.json.tftpl", {
    env                   = var.env
    metric_days_to_expiry = var.metric_acm_days_to_expiry
    metric_crl_hours      = var.metric_crl_hours_until_next_update
    hsm_device_namespace  = var.hsm_device_namespace
    cert_critical_days    = var.cert_critical_days
    crl_critical_hours    = var.crl_critical_hours
  })
}
