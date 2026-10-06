# Runbook — CRL stale, expired or unreachable

**Triggers**: Datadog `[PKI] CRL close to expiry`, synthetic `[PKI] CRL reachable`,
CloudWatch alarms `*-crl-stale-*` / `*-crl-unreachable-*`, Splunk `PKI - CRL stale or unreachable`.

**Why it is critical**: when `nextUpdate` passes, hard-fail clients (many mTLS stacks,
Windows CAPI in some configurations, Java with revocation enabled, network appliances)
reject **every certificate issued by that CA**. Treat "less than 25 % of CRL lifetime
left" as P1.

## 1. Check what clients see

```bash
python scripts/check_crl.py http://crl.pki.example.com/crl/<ca-id>.crl
curl -sI http://crl.pki.example.com/crl/<ca-id>.crl          # HTTP status, Age, X-Cache
```

## 2. Locate the break

| Observation | Cause | Action |
| --- | --- | --- |
| HTTP 403/404 from CloudFront | Object missing, OAC / bucket policy changed | `aws s3 ls s3://<crl-bucket>/crl/`; diff bucket policy with Terraform (`terraform plan` shows drift) |
| Object in S3 is fresh, CloudFront serves old | Cache | `aws cloudfront create-invalidation --distribution-id <id> --paths '/crl/*'`; check cache policy TTL |
| Object in S3 is old | PCA cannot write the CRL | EventBridge event "ACM Private CA CRL Generation" with `result=failure`; CloudWatch metric `MisconfiguredCRLBucket`; check bucket policy statement `AllowPrivateCAToWriteCRLs` and Object Ownership |
| CA disabled / deleted | CA state | `aws acm-pca describe-certificate-authority --certificate-authority-arn <arn>` |
| **Offline root CRL** close to expiry | Ceremony not scheduled | Emergency key ceremony to re-sign the root CRL (`external-root-signing.md`, section "Root CRL") |

AWS Private CA regenerates the CRL automatically about every 30 minutes after a
revocation and before expiry; a stale CRL almost always means it cannot write to S3.

## 3. Verify recovery

- `check_crl.py` shows `Time left` close to the full CRL validity.
- CloudWatch `PKI/CRL HoursUntilNextUpdate` back above the threshold; Datadog monitor OK.

## 4. Prevent

- Never edit the CRL bucket policy outside Terraform.
- Root CRL re-signing is a recurring calendar event (at least 60 days before nextUpdate).
