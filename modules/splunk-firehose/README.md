# Module `splunk-firehose`

```text
Streams PKI CloudWatch log groups to Splunk HTTP Event Collector (HEC)
through Amazon Data Firehose, in near real time:

  /aws/events/pki-*            (every ACM / Private CA event)   \
  /aws/lambda/*crl-checker*    (CRL freshness checks)            >--> subscription filter
  /aws/lambda/*distributor*    (certificate redistribution)     /        |
                                                                         v
             Firehose (decompress + extract CW Logs messages) --> Splunk HEC
                                |  failed events only
                                v
                             S3 backup bucket (replay)

CloudTrail itself goes to Splunk through the SQS-based S3 input
(module pki-audit-logging), which is the pattern Splunk recommends for
high-volume AWS logs.

The HEC token is NEVER passed to Terraform: Firehose reads it from Secrets
Manager at runtime (secret JSON: {"hec_token":"<token>"}).
```

Usage examples: the root modules in `environments/` and the cookbook in the root [README](../../README.md).

## Inputs

| Name | Description | Type | Required |
| --- | --- | --- | --- |
| `name_prefix` | Prefix for resource names. | `string` | **yes** |
| `hec_endpoint` | Splunk HEC endpoint reachable by Firehose, e.g. https://http-inputs-firehose-<stack>.splunkcloud.com:443 or your on-prem HEC load balancer. | `string` | **yes** |
| `hec_token_secret_arn` | Secrets Manager secret ARN containing {\"hec_token\":\"...\"} (created outside Terraform so the token never reaches the state). | `string` | **yes** |
| `log_group_names` | CloudWatch log groups to stream to Splunk. | `list(string)` | **yes** |
| `backup_bucket_name` | Bucket for events Splunk failed to accept. | `string` | **yes** |
| `tags` | Tags. | `map(string)` | no |

## Outputs

| Name | Description |
| --- | --- |
| `delivery_stream_arn` | Firehose stream ARN. |
| `backup_bucket_name` | Failed-events bucket (replay with the Splunk add-on or a Firehose re-ingest). |
