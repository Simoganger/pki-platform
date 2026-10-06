# Module `pca-root-ca`

```text
Creates a ROOT certificate authority in AWS Private CA and self-signs it.

WHEN TO USE
  - Non-production / lab PKI hierarchies.
  - Production ONLY if your CP/CPS allows a cloud-hosted root. In most
    regulated banks the production root stays OFFLINE in an on-premises HSM
    (Thales Luna / Utimaco) and AWS hosts only the issuing CAs - see the
    `pca-subordinate-ca` module with `signing_mode = "EXTERNAL"`.

WHAT IT CREATES
  1. aws_acmpca_certificate_authority             (type = ROOT)
  2. aws_acmpca_certificate                       (self-signed root cert)
  3. aws_acmpca_certificate_authority_certificate (installs the cert -> CA becomes ACTIVE)
```

Usage examples: the root modules in `environments/` and the cookbook in the root [README](../../README.md).

## Inputs

| Name | Description | Type | Required |
| --- | --- | --- | --- |
| `name` | Short logical name of the CA (used in tags), e.g. \"bnc-lab-root-g1\". | `string` | **yes** |
| `subject` | X.509 subject of the root CA certificate. | `object(...)` | **yes** |
| `key_algorithm` | Key algorithm of the root CA. RSA_4096 maximizes compatibility for a long-lived root; EC_secp384r1 is a strong modern choice. | `string` | no |
| `signing_algorithm` | Signature algorithm used by the root (must match the key family: SHA*WITHRSA for RSA, SHA*WITHECDSA for EC, ML_DSA_* for ML-DSA). | `string` | no |
| `key_storage_security_standard` | FIPS level of the AWS-managed HSM that stores the CA key. | `string` | no |
| `validity_years` | Validity of the self-signed root certificate, in years. | `number` | no |
| `crl` | CRL publication settings. The bucket must allow acm-pca.amazonaws.com to write (module crl-distribution does this). | `object(...)` | no |
| `permanent_deletion_time_in_days` | Restore window (7-30 days) after a delete request. | `number` | no |
| `tags` | Tags applied to every resource (owner, data_classification, cost center...). | `map(string)` | no |

## Outputs

| Name | Description |
| --- | --- |
| `arn` | ARN of the root CA. |
| `id` | ID of the root CA (last part of the ARN; also the CRL object name). |
| `certificate_pem` | Root certificate (PEM). Distribute it to trust stores (GPO, MDM, base images, Java cacerts...). |
| `key_algorithm` | Key algorithm of the root (children must sign with a matching signing algorithm family). |
| `signing_algorithm` | Signing algorithm the root uses when signing subordinate CAs. |
| `certificate_authority_certificate_id` | Dependency handle: reference it to make sure the CA is ACTIVE before issuing. |
