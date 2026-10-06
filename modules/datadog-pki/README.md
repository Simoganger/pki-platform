# Module `datadog-pki`

```text
Datadog monitors, synthetic tests and a dashboard for the PKI.

PREREQUISITES (usually owned by the observability team, not this repo):
  - Datadog AWS integration on the PKI accounts with the "CertificateManager"
    and "ACMPrivateCA" namespaces enabled, and custom CloudWatch namespaces
    collected (PKI/CRL, PKI/Security).
  - Datadog Forwarder (or Amazon Data Firehose) shipping CloudTrail and the
    /aws/events/pki-* log groups to Datadog Logs.
  - Datadog Agent with the SNMP integration on a relay host in the HSM
    management network (observability/datadog-agent/conf.d/snmp.d/conf.yaml).
  - A Synthetics PRIVATE location inside the network for endpoints using the
    internal PKI (public locations neither reach nor trust them).

METRIC NAMES: Datadog derives metric names from CloudWatch. The defaults
below are what Datadog publishes for these namespaces at the time of writing;
confirm them in Metrics Explorer and override the variables if needed.
```

Usage examples: the root modules in `environments/` and the cookbook in the root [README](../../README.md).

## Inputs

| Name | Description | Type | Required |
| --- | --- | --- | --- |
| `env` | Environment tag value (nonprod, prod). | `string` | **yes** |
| `notify_handles` | Datadog notification handles, e.g. [\"@pagerduty-pki\", \"@slack-pki-alerts\", \"@pki-team@example.com\"]. | `list(string)` | **yes** |
| `security_notify_handles` | Extra handles for security monitors (SOC). | `list(string)` | no |
| `runbook_base_url` | Base URL of the runbooks (docs/runbooks in this repository). | `string` | **yes** |
| `metric_acm_days_to_expiry` | Datadog metric for ACM DaysToExpiry. | `string` | no |
| `metric_crl_hours_until_next_update` | Datadog metric for the PKI/CRL HoursUntilNextUpdate custom CloudWatch metric (check the exact name Datadog assigns to custom namespaces). | `string` | no |
| `cert_warning_days` | Warning threshold in days. | `number` | no |
| `cert_critical_days` | Critical threshold in days. | `number` | no |
| `crl_warning_hours` | CRL warning threshold (hours before nextUpdate). | `number` | no |
| `crl_critical_hours` | CRL critical threshold (hours before nextUpdate). | `number` | no |
| `crl_urls` | CRL URLs checked by HTTP synthetics, keyed by CA name. | `map(string)` | no |
| `tls_endpoints` | TLS endpoints checked by SSL synthetics. Use private location IDs for internal endpoints. | `list(...)` | no |
| `synthetics_locations` | Default synthetics locations, e.g. [\"aws:ca-central-1\"] or [\"pl:bnc-private-location-xxxx\"]. | `list(string)` | no |
| `hsm_monitoring_enabled` | Create the HSM SNMP monitor. | `bool` | no |
| `hsm_device_namespace` | Datadog device_namespace configured on the SNMP instances of the HSMs. | `string` | no |

## Outputs

| Name | Description |
| --- | --- |
| `dashboard_url` | URL path of the PKI dashboard. |
| `monitor_ids` | IDs of the monitors created. |
