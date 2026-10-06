# Module `pca-subordinate-ca`

```text
Creates an ISSUING (subordinate) CA in AWS Private CA. This is the CA that
actually signs end-entity certificates for servers, workloads and devices.

TWO SIGNING MODES

  signing_mode = "PCA"       Parent CA is another AWS Private CA (lab / nonprod
                             root created by module pca-root-ca). Fully automatic,
                             single apply.

  signing_mode = "EXTERNAL"  Parent is an OFFLINE root in an on-prem HSM
                             (production pattern). Two applies:
                               1) apply -> CA is created in PENDING_CERTIFICATE
                                  state and its CSR is exposed in output `csr_pem`.
                               2) The CSR is signed during a key ceremony
                                  (docs/runbooks/external-root-signing.md),
                                  then the signed cert + chain are set in
                                  `external_signed_certificate` and applied.

OPTIONAL HARDENING
  - Name constraints (RFC 5280 4.2.1.10): restricts which DNS names this CA
    can ever sign. Clients reject any certificate outside the permitted
    subtrees. Build the DER value with scripts/build_name_constraints.py.
  - OCSP (AWS-managed responder) in addition to the CRL.
  - ACM permission so ACM can issue and AUTO-RENEW private certificates.
```

Usage examples: the root modules in `environments/` and the cookbook in the root [README](../../README.md).

## Inputs

| Name | Description | Type | Required |
| --- | --- | --- | --- |
| `name` | Logical CA name, e.g. \"servers-issuing-g1\". | `string` | **yes** |
| `usage` | What this CA is for (tag pki:usage). Keep one CA per usage / risk zone. | `string` | **yes** |
| `subject` | X.509 subject of the issuing CA. | `object(...)` | **yes** |
| `usage_mode` | GENERAL_PURPOSE (any validity) or SHORT_LIVED_CERTIFICATE (max 7 days, much cheaper per certificate, revocation rarely needed). | `string` | no |
| `key_algorithm` | Key algorithm of the issuing CA. | `string` | no |
| `signing_algorithm` | Algorithm THIS CA uses to sign end-entity certs and CRLs (must match key_algorithm family). | `string` | no |
| `key_storage_security_standard` | FIPS level of the AWS-managed HSM that stores the CA key. | `string` | no |
| `signing_mode` | PCA = signed by an AWS Private CA parent. EXTERNAL = signed offline by an on-prem HSM root (two-phase apply). | `string` | no |
| `parent_ca_arn` | ARN of the parent AWS Private CA (signing_mode = PCA). | `string` | no |
| `parent_signing_algorithm` | Signing algorithm of the PARENT (matches the parent's key), e.g. SHA512WITHRSA for an RSA root. | `string` | no |
| `validity_years` | Validity of the issuing CA certificate (signing_mode = PCA). Must end before the parent's own expiry. | `number` | no |
| `external_signed_certificate` | Phase 2 of signing_mode = EXTERNAL: the PEM certificate signed by the offline root, and its chain (root PEM, plus intermediates if any). | `object(...)` | no |
| `name_constraints_der_base64` | Optional base64 DER value of a NameConstraints extension (scripts/build_name_constraints.py). Restricts the DNS names this CA can sign. | `string` | no |
| `crl` | CRL settings. Issuing CAs use short CRLs (default 7 days) so revocations propagate quickly. | `object(...)` | no |
| `ocsp` | AWS-managed OCSP responder. custom_cname requires a DNS CNAME to the regional ocsp.acm-pca endpoint. | `object(...)` | no |
| `allow_acm_managed_renewal` | Grant acm.amazonaws.com the permissions needed to issue and auto-renew ACM private certificates. | `bool` | no |
| `resource_policy_json` | Optional resource-based policy for the CA (cross-account issuance through RAM). | `string` | no |
| `enabled` | Set to false to DISABLE issuance (e.g. during an incident) without deleting the CA. | `bool` | no |
| `permanent_deletion_time_in_days` | Restore window (7-30 days) after a delete request. | `number` | no |
| `tags` | Tags applied to the CA. | `map(string)` | no |

## Outputs

| Name | Description |
| --- | --- |
| `arn` | ARN of the issuing CA. Pass it to ACM (certificate_authority_arn) or to RAM shares. |
| `id` | CA ID (CRL object name: crl/<id>.crl). |
| `csr_pem` | CSR of the CA. In EXTERNAL mode, hand it to the key ceremony to be signed by the offline root. |
| `certificate_pem` | Installed CA certificate (null until installed). |
| `status_hint` | Human-readable state of the CA lifecycle. |
| `crl_url` | Public CRL URL embedded in issued certificates (CDP). |
| `usage_mode` | GENERAL_PURPOSE or SHORT_LIVED_CERTIFICATE. |

## Tests

```bash
terraform init -backend=false && terraform test   # mocked providers, no AWS access
```
