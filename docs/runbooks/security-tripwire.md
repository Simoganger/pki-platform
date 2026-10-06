# Runbook — PKI security tripwire

**Triggers**: CloudWatch alarms `pki-security-*`, Datadog `[PKI] Sensitive AWS Private CA API call`,
Splunk saved searches (out-of-band trust change, key export, issuance spike, ADCS ESC1,
ADCS template change, HSM authentication failures).

Treat as a **security incident until proven otherwise**. Involve the SOC immediately for
`pca-destructive`, `pca-trust-change`, `acm-export`, `logging-tamper`, ESC1.

## 1. Collect facts (do not change anything yet)

```spl
`pki_cloudtrail` eventSource IN ("acm-pca.amazonaws.com","acm.amazonaws.com","ram.amazonaws.com","cloudtrail.amazonaws.com")
| table _time eventName userIdentity.arn userIdentity.sessionContext.sessionIssuer.userName sourceIPAddress userAgent requestParameters.* errorCode
```

Questions: who (`userIdentity.arn`), from where (`sourceIPAddress`, `userAgent`), which
resource, did it succeed (`errorCode`), is there a matching change ticket or break-glass
record?

## 2. Decide

| Finding | Action |
| --- | --- |
| Approved break-glass action with ticket | Document, close, verify Terraform reconciles (drift) |
| Unknown or unapproved | Escalate to SOC (P1), continue with section 3 |

## 3. Contain (with the SOC)

- **Rogue issuance / unknown change on a CA**: disable issuance — set `enabled = false` on the CA (pipeline) or, if the pipeline is suspected, break-glass `aws acm-pca update-certificate-authority --status DISABLED`.
- **Permission / RAM change**: revert through a Terraform apply (it restores the declared state).
- **Key exported by an unknown identity**: revoke the certificate (`certificate-revocation.md`, reason `KEY_COMPROMISE`) and re-issue.
- **ESC1 on ADCS**: revoke the certificate, disable the account, remove the template from the CA, fix the template flags (no *Supply in the request*), run Certipy/Locksmith on all templates.
- **Logging tampered**: restore the trail via Terraform; Object Lock protects existing logs.
- Revoke the session: deny-all inline policy with `aws:TokenIssueTime` condition on the role, rotate credentials of the identity.

## 4. Scope

```bash
python scripts/pca_audit_report.py --ca-arn <arn> --bucket <crl-bucket> --format CSV --output audit.csv
```

List every certificate issued during the window; revoke anything not traceable to a
legitimate request. If the CA key itself may be compromised: `ca-compromise.md`.

## 5. Close

Post-mortem, detection tuning, and a code change that would have prevented it.
