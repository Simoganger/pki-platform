# Runbook — Certificate renewal failure / certificate expiring

**Triggers**: Datadog `[PKI] ACM certificate expires soon`, `[PKI] ACM renewal requires action`,
CloudWatch alarm `pki-cert-expiry-*`, EventBridge "ACM Certificate Approaching Expiration /
Expired / Renewal Action Required", distributor DLQ alarm, `cert-inventory` issue.

**Severity**: P2 if > 7 days left, **P1 if < 7 days** or already expired (outage).

## 1. Identify

```bash
ARN=arn:aws:acm:ca-central-1:<acct>:certificate/<id>
aws acm describe-certificate --certificate-arn "$ARN" \
  --query 'Certificate.{Name:DomainName,Type:Type,Status:Status,NotAfter:NotAfter,Eligibility:RenewalEligibility,Renewal:RenewalSummary,InUse:InUseBy,CA:CertificateAuthorityArn}'
aws acm list-tags-for-certificate --certificate-arn "$ARN"   # pki:owner -> who to call
```

## 2. Diagnose by certificate type

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| `RenewalSummary.RenewalStatusReason = PCA_INVALID_STATE` | Issuing CA disabled, expired or deleted | Check CA: `aws acm-pca describe-certificate-authority`. Re-enable (`enabled = true` in Terraform) or move the cert to the new CA |
| `PCA_ACCESS_DENIED` / `PCA_INVALID_PERMISSIONS` | `acm.amazonaws.com` permission missing on the CA | `allow_acm_managed_renewal = true` in the CA module; for RAM-shared CAs check the share still includes the account |
| `RenewalEligibility = INELIGIBLE` (private cert) | Certificate not associated and never exported | Associate it with its resource or export it once (distributor), or re-request |
| Public cert `PENDING_VALIDATION` | DNS validation CNAME deleted | Re-create the record (Terraform apply of `acm-public-certificate`) |
| Renewed in ACM but host still serves the old cert | Distribution failed (DLQ not empty) or SSM command failed | See section 3 |
| CA itself expires soon (inventory, 540-day threshold) | Planned rotation missing | `ca-rotation.md` — this is not an incident yet, but schedule it now |

## 3. Exported certificates (EC2 / on-prem)

```bash
# Messages that failed
aws sqs receive-message --queue-url <dlq_url> --max-number-of-messages 10
# Lambda logs (structured JSON)
aws logs tail /aws/lambda/<prefix>-acm-renewal-distributor --since 2d --filter-pattern '"pki.cert"'
# Re-run the distribution manually
aws lambda invoke --function-name <prefix>-acm-renewal-distributor \
  --cli-binary-format raw-in-base64-out --payload "{\"certificateArn\":\"$ARN\"}" /dev/stdout
# SSM command result on the hosts
aws ssm list-command-invocations --command-id <id> --details
```

On the host: `journalctl -t pki-cert-sync`, then run `/usr/local/bin/pki-cert-sync.sh <secret>`.

## 4. Emergency (< 24 h, renewal impossible)

1. Request a **new** certificate with the same names (new module instance or `terraform apply -replace` in the owner's workspace — `create_before_destroy` keeps the listener valid).
2. Attach it to the resource; for exported certificates run the distributor manually.
3. Verify from a client: `openssl s_client -connect host:443 -servername host </dev/null | openssl x509 -noout -dates`.

## 5. Close

- Confirm the Datadog monitor and CloudWatch alarm return to OK.
- Post-mortem if the certificate expired: why did alerting not lead to action (owner missing? alert routed nowhere?). Add the fix to the module or monitoring, not only to this case.
