# Runbook — Issuing CA compromise (major incident)

An attacker could issue trusted certificates for anything the CA is allowed to sign
(name constraints limit the damage). Declare a **major incident** with the SOC, risk
management and the CISO office.

## 1. Stop issuance (minutes)

- Disable the CA: `enabled = false` (pipeline) or break-glass
  `aws acm-pca update-certificate-authority --certificate-authority-arn <arn> --status DISABLED`.
- Remove it from RAM shares (`share_with = []`) so consumer accounts cannot issue.
- Preserve evidence: CloudTrail (Object Lock), PCA audit report, HCP Terraform run history.

## 2. Revoke the CA at the parent (hours)

- **Nonprod (PCA root)**: revoke the issuing CA certificate with the root
  (`aws acm-pca revoke-certificate` on the root ARN with the issuing CA serial,
  reason `CERTIFICATE_AUTHORITY_COMPROMISE`).
- **Prod (offline root)**: emergency key ceremony: add the issuing CA serial to the root
  CRL, publish the new root CRL (`external-root-signing.md`).

## 3. Rebuild (hours to days)

1. Create `<name>-g<N+1>` (new key) — `ca-rotation.md` phase 1, in emergency mode.
2. Point every consumer at the new CA: one PR changing `certificate_authority_arn` (ACM
   issues new certificates; `create_before_destroy` avoids listener gaps).
3. Re-issue Windows (Connector for AD) and Kubernetes certificates (cert-manager issues
   new ones as soon as the issuer points to the new CA).
4. Inventory: nothing must remain on the compromised CA.

## 4. Communicate and learn

Regulators / card brands notification per the incident policy (PCI DSS 12.10), customer
impact assessment, post-mortem, control improvements.

Infrastructure as code is what makes step 3 realistic: rebuilding a CA hierarchy by hand
takes weeks; here it is a few reviewed pull requests.
