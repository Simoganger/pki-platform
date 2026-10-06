# Module `acm-public-certificate`

```text
Publicly trusted certificate from Amazon's public CA, validated by DNS
(Route 53). ACM renews it automatically as long as the validation CNAME
records stay in place - NEVER delete them.

Why it matters in 2026: CA/Browser Forum ballot SC-081v3 caps public TLS
certificates at 200 days (since 2026-03-15), 100 days (2027-03-15) and
47 days (2029-03-15). Manual renewal of public certs is no longer viable;
DNS-validated ACM certificates renew without human action.
```

Usage examples: the root modules in `environments/` and the cookbook in the root [README](../../README.md).

## Inputs

| Name | Description | Type | Required |
| --- | --- | --- | --- |
| `domain_name` | Public DNS name, e.g. crl.pki.example.com. | `string` | **yes** |
| `subject_alternative_names` | Additional public names. | `list(string)` | no |
| `route53_zone_id` | Public hosted zone used for DNS validation. | `string` | **yes** |
| `key_algorithm` | RSA_2048 for maximum client compatibility, EC_prime256v1 for modern clients. | `string` | no |
| `owner` | Owning team. | `string` | **yes** |
| `tags` | Tags. | `map(string)` | no |

## Outputs

| Name | Description |
| --- | --- |
| `arn` | ARN of the validated certificate. |
| `not_after` | Expiry of the current certificate. |
