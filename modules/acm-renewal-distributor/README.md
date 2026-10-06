# Module `acm-renewal-distributor`

```text
Closes the auto-renewal loop for workloads that are NOT integrated with ACM
(EC2 with nginx/Apache/IIS, containers, on-prem servers reached via SSM).

  ACM renews the cert  --> EventBridge "ACM Certificate Available"
       --> Lambda: exports cert + key from ACM, stores them in Secrets Manager
           (KMS-encrypted, readable only by the workload role named in the
           certificate tag pki:reader-role)
       --> optional SSM Run Command on instances tagged pki:cert=<value>
           runs /usr/local/bin/pki-cert-sync.sh to install + reload
       --> SNS notification + structured log (Splunk / Datadog)

Only certificates tagged pki:distribute=secretsmanager are processed (set by
module acm-private-certificate when `distribution` is configured).

SECURITY NOTES
  - Exporting a private key is a sensitive operation: acm:ExportCertificate
    is granted ONLY to this Lambda role, and only on certificates carrying the
    opt-in tag (ABAC condition).
  - The key never touches Terraform state or GitHub; it lives in ACM and in
    one KMS-encrypted secret.
  - Prefer ACM-integrated services (ALB, API GW, CloudFront) whenever possible:
    the key is then never exported at all.
```

Usage examples: the root modules in `environments/` and the cookbook in the root [README](../../README.md).

## Inputs

| Name | Description | Type | Required |
| --- | --- | --- | --- |
| `name_prefix` | Prefix for resource names, e.g. \"pki-nonprod\". | `string` | **yes** |
| `lambda_source_dir` | Directory containing the BUILT Lambda package (handler.py + vendored cryptography). Build with `make lambda-build`. | `string` | **yes** |
| `secret_name_prefix` | Prefix of the Secrets Manager secrets created for certificates. | `string` | no |
| `notification_topic_arn` | SNS topic notified after each redistribution (module pki-monitoring output). | `string` | **yes** |
| `log_retention_days` | Lambda log retention (PCI DSS 10.5.1: 12 months). | `number` | no |
| `logs_kms_key_arn` | Optional KMS key for the log group. | `string` | no |
| `tags` | Tags. | `map(string)` | no |

## Outputs

| Name | Description |
| --- | --- |
| `lambda_function_name` | Name of the distributor function (invoke manually for a first distribution: {\"certificateArn\": \"...\"}). |
| `secrets_kms_key_arn` | KMS key protecting certificate secrets. Workload roles need kms:Decrypt on it. |
| `ssm_document_name` | SSM document used to reload certificates on hosts. |
| `dlq_url` | Dead-letter queue (failed distributions). |
