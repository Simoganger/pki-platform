# Module `pki-monitoring`

```text
Native AWS observability for the PKI, designed to feed Datadog and Splunk:

  1. SNS topic "pki-alerts" (KMS-encrypted)      -> email / PagerDuty / Datadog
  2. EventBridge rules on ACM + AWS Private CA events
       -> SNS (actionable ones) and -> CloudWatch Logs /aws/events/pki
          (ALL of them; the log group is streamed to Splunk by module
           splunk-firehose and/or collected by the Datadog Forwarder)
  3. CRL freshness checker (Lambda, every 15 min): downloads each CRL, reads
     its nextUpdate field and publishes PKI/CRL metrics. An expired CRL makes
     hard-fail clients reject EVERY certificate of that CA - this is the most
     under-monitored failure mode in PKI.
  4. CloudWatch alarms on those metrics.
```

Usage examples: the root modules in `environments/` and the cookbook in the root [README](../../README.md).

## Inputs

| Name | Description | Type | Required |
| --- | --- | --- | --- |
| `name_prefix` | Prefix for resource names, e.g. \"pki-prod\". | `string` | **yes** |
| `alert_emails` | E-mail addresses subscribed to the PKI alert topic (confirmation required). | `list(string)` | no |
| `alert_https_endpoints` | HTTPS endpoints subscribed to the topic (Datadog AWS SNS integration URL, PagerDuty...). | `list(string)` | no |
| `crl_urls` | CRL URLs to watch, keyed by a STABLE name (e.g. CA name). A map (not a list) because URLs contain CA IDs unknown until apply, and for_each keys must be known at plan time. | `map(string)` | no |
| `crl_min_hours_remaining` | Alarm when a CRL's nextUpdate is closer than this many hours. Rule of thumb: 25% of the CRL validity. | `number` | no |
| `crl_checker_source_dir` | Path to lambda/crl_freshness_checker (stdlib only, no build needed). | `string` | **yes** |
| `log_retention_days` | Retention of PKI event logs (PCI DSS 10.5.1 requires 12 months). | `number` | no |
| `tags` | Tags. | `map(string)` | no |

## Outputs

| Name | Description |
| --- | --- |
| `alerts_topic_arn` | SNS topic for PKI alerts. |
| `events_log_group_name` | Log group receiving every ACM / PCA event (stream it to Splunk / Datadog). |
| `events_log_group_arn` | ARN of the events log group. |
| `kms_key_arn` | KMS key used by SNS and the log groups. |
| `crl_checker_log_group_name` | Log group of the CRL checker. |
