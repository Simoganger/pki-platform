# Module `crl-distribution`

```text
Publishes CRLs written by AWS Private CA to a private S3 bucket and serves
them over HTTP through CloudFront.

WHY THIS DESIGN
  - The CRL Distribution Point (CDP) URL is embedded in EVERY certificate a CA
    issues. It must stay reachable for the life of those certificates, so it
    points to a stable DNS name you own (crl.pki.example.com), never to a raw
    bucket URL.
  - CRLs are served over plain HTTP on purpose: a client validating an HTTPS
    certificate cannot depend on HTTPS to fetch revocation data (circular
    dependency). CRLs are signed, so integrity does not rely on TLS.
  - The bucket keeps S3 Block Public Access ON. PCA writes with
    BUCKET_OWNER_FULL_CONTROL; only CloudFront (Origin Access Control) reads.

OBJECT LAYOUT (written by PCA):   crl/<ca-id>.crl
```

Usage examples: the root modules in `environments/` and the cookbook in the root [README](../../README.md).

## Inputs

| Name | Description | Type | Required |
| --- | --- | --- | --- |
| `bucket_name` | Globally unique name of the CRL bucket. | `string` | **yes** |
| `aliases` | Stable DNS names for the CDP, e.g. [\"crl.pki.example.com\"]. Must match the custom_cname of the CAs. | `list(string)` | no |
| `alias_acm_certificate_arn_us_east_1` | ACM certificate (us-east-1) covering the aliases. Required by CloudFront when aliases are set. | `string` | no |
| `route53_zone_id` | Hosted zone in which to create alias records for the CDP names (optional). | `string` | no |
| `cache_ttl_seconds` | CloudFront TTL for CRLs. Keep it well below the CRL publication interval. | `number` | no |
| `price_class` | CloudFront price class. | `string` | no |
| `noncurrent_crl_retention_days` | How long previous CRL versions are kept. | `number` | no |
| `access_log_bucket` | Optional bucket name for S3 / CloudFront access logs. | `string` | no |
| `tags` | Tags. | `map(string)` | no |

## Outputs

| Name | Description |
| --- | --- |
| `bucket_name` | Name of the CRL bucket (pass to the CA modules as crl.s3_bucket_name). |
| `bucket_arn` | ARN of the CRL bucket. |
| `distribution_domain_name` | CloudFront domain name (use it as custom_cname if you have no alias yet). |
| `distribution_id` | CloudFront distribution ID (needed for cache invalidations). |
| `cdp_hostname` | Hostname to use as custom_cname in the CA modules. |
