# Module `pki-audit-logging`

```text
Tamper-evident audit trail for the PKI account (PCI DSS requirement 10):

  CloudTrail (multi-region, log file validation, KMS)
    -> S3 bucket (versioned, optional Object Lock = WORM)
         -> SNS -> SQS  : Splunk Add-on for AWS "SQS-based S3" input pulls
                          every new CloudTrail file (role + external ID below)
    -> CloudWatch Logs  : metric filters on sensitive AWS Private CA / ACM /
                          KMS / CloudTrail API calls -> alarms -> SNS

The metric filters are the "tripwires": any destructive or trust-changing
call (delete/disable a CA, change its policy or permissions, stop logging)
that does NOT come from the HCP Terraform apply role raises an alarm.
```

Usage examples: the root modules in `environments/` and the cookbook in the root [README](../../README.md).

## Inputs

| Name | Description | Type | Required |
| --- | --- | --- | --- |
| `trail_name` | Name of the CloudTrail trail. | `string` | **yes** |
| `bucket_name` | Globally unique name of the trail bucket. | `string` | **yes** |
| `is_organization_trail` | true if deployed from the Organizations management / delegated admin account. | `bool` | no |
| `object_lock` | S3 Object Lock (WORM). Can only be enabled at bucket creation. | `object(...)` | no |
| `retention_days` | Total retention of CloudTrail files in S3. | `number` | no |
| `cloudwatch_retention_days` | Retention in CloudWatch Logs (hot search for tripwires). | `number` | no |
| `alerts_topic_arn` | SNS topic receiving tripwire alarms (module pki-monitoring). | `string` | **yes** |
| `trusted_automation_role_name_patterns` | IAM role NAMES (wildcards allowed) whose changes are expected (HCP Terraform apply role). | `list(string)` | no |
| `log_admin_role_arns` | Role ARNs (wildcards allowed) allowed to delete trail objects / change lifecycle. Keep it to break-glass. | `list(string)` | **yes** |
| `splunk` | Splunk Add-on for AWS (SQS-based S3 input) integration. | `object(...)` | no |
| `access_log_bucket` | Optional central S3 access-log bucket for the trail bucket. | `string` | no |
| `tags` | Tags. | `map(string)` | no |

## Outputs

| Name | Description |
| --- | --- |
| `trail_arn` | CloudTrail trail ARN. |
| `trail_bucket_name` | Bucket holding CloudTrail files. |
| `cloudwatch_log_group_name` | Log group with CloudTrail events (Datadog can subscribe to it). |
| `splunk_sqs_queue_url` | Queue to configure in the Splunk Add-on for AWS (SQS-based S3 input). |
| `splunk_reader_role_arn` | Role the Splunk add-on assumes (with the external ID). |
| `kms_key_arn` | KMS key encrypting the trail. |
