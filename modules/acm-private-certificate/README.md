# Module `acm-private-certificate`

```text
Requests a PRIVATE certificate in AWS Certificate Manager, issued by an AWS
Private CA (owned by this account or shared through RAM).

AUTO-RENEWAL
  ACM renews private certificates automatically before expiry (managed
  renewal) as long as:
    1. the issuing CA is ACTIVE and GENERAL_PURPOSE (ACM cannot use a
       SHORT_LIVED_CERTIFICATE CA),
    2. acm.amazonaws.com has IssueCertificate/GetCertificate/ListPermissions
       on the CA (module pca-subordinate-ca: allow_acm_managed_renewal), and
    3. for integrated services (ALB, NLB, CloudFront, API Gateway) - nothing
       else to do: the renewed cert is deployed transparently.
  For EC2 / on-prem / containers that use an EXPORTED copy, ACM emits
  "ACM Certificate Available" after renewal; module acm-renewal-distributor
  catches it and redistributes the new certificate.

GUARDRAILS BUILT IN
  - Every name must end with one of `allowed_domain_suffixes` (no wildcard
    unless allow_wildcard = true). This mirrors the CA name constraints and
    gives a clear error at PLAN time instead of a rejected certificate later.
  - Mandatory owner tag so expiry alerts reach a human.
```

Usage examples: the root modules in `environments/` and the cookbook in the root [README](../../README.md).

## Inputs

| Name | Description | Type | Required |
| --- | --- | --- | --- |
| `domain_name` | Primary DNS name (CN), e.g. payments-api.internal.example.com. | `string` | **yes** |
| `subject_alternative_names` | Additional DNS names (SAN). | `list(string)` | no |
| `certificate_authority_arn` | ARN of the issuing AWS Private CA (owned or shared through RAM). Must be GENERAL_PURPOSE. | `string` | **yes** |
| `key_algorithm` | Key algorithm of the certificate key pair (generated and kept by ACM). | `string` | no |
| `allowed_domain_suffixes` | DNS suffixes this team is allowed to request (mirrors the CA name constraints). | `list(string)` | **yes** |
| `allow_wildcard` | Allow *.domain names (needs a PKI exception). | `bool` | no |
| `owner` | Owning team or distribution list (receives expiry alerts). Mandatory. | `string` | **yes** |
| `application` | Application identifier (CMDB ID). | `string` | **yes** |
| `distribution` | Optional redistribution of the certificate to non-integrated workloads (EC2, on-prem, containers) after each renewal, handled by module acm-renewal-distributor: method = "secretsmanager" secret_name = optional custom secret name reader_role_arn = IAM role of the workload allowed to read the secret ssm_target_tag_value = optional: instances tagged pki:cert=<value> get an SSM Run Command that reloads the certificate | `object(...)` | no |
| `expiry_alarm` | CloudWatch alarm on AWS/CertificateManager DaysToExpiry. | `object(...)` | no |
| `tags` | Additional tags. | `map(string)` | no |

## Outputs

| Name | Description |
| --- | --- |
| `arn` | ACM certificate ARN (attach it to an ALB listener, API Gateway domain, etc.). |
| `domain_name` | Primary name. |
| `not_after` | Expiry timestamp of the current certificate. |
| `renewal_eligibility` | ELIGIBLE means ACM will renew it automatically. |
| `secret_name` | Secrets Manager secret receiving the exported certificate (if distribution is enabled). |

## Tests

```bash
terraform init -backend=false && terraform test   # mocked providers, no AWS access
```
