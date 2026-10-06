# Runbook — Revoke a certificate

**When**: private key compromised or suspected, server decommissioned, employee or
partner leaving (client certificates), certificate issued in error.

Revocation is **irreversible** in AWS Private CA. Make sure a replacement exists first
when the service must keep running.

## 1. Choose the reason (RFC 5280)

| Situation | Reason |
| --- | --- |
| Key stolen, leaked, exposed in a repo or log | `KEY_COMPROMISE` |
| Replaced by a new certificate | `SUPERSEDED` |
| Service decommissioned | `CESSATION_OF_OPERATION` |
| Holder left / changed role | `AFFILIATION_CHANGED` |
| Access withdrawn | `PRIVILEGE_WITHDRAWN` |

## 2. Revoke

```bash
scripts/revoke_certificate.sh <ca-arn> <certificate-arn> <REASON> <CHG|INC|SECnnnnnn>
```

For certificates managed by ACM, the certificate ARN in PCA is visible in the ACM
certificate details or in the PCA audit report.

## 3. Propagation

- OCSP (if enabled): almost immediate.
- CRL: next generation (about 30 minutes), then CloudFront TTL (default 5 minutes).
  Urgent: invalidate `/crl/*` on the distribution.
- Clients with cached CRLs keep the old one until its `nextUpdate`: another reason for
  short CRL lifetimes on issuing CAs (7 days, 1 day for short-lived CAs).

## 4. Verify and record

```bash
python scripts/check_crl.py http://crl.pki.example.com/crl/<ca-id>.crl --serial 0x<hex-serial>
```

Record the revocation (who, why, ticket) — Splunk keeps the CloudTrail evidence.
