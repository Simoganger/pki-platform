## What changes

<!-- One or two sentences. Link the change ticket (CHG...) for production. -->

Ticket:

## PKI impact checklist

- [ ] No CA is created, replaced or deleted - or this is a planned CA operation with its runbook linked
- [ ] No change to a CA subject, key algorithm or CRL hostname (these force replacement / break issued certificates)
- [ ] New certificates have an owner tag and are inside the allowed domain suffixes
- [ ] RAM sharing only widened to explicit OUs / accounts (never the organization root)
- [ ] Alerting still covers the change (Datadog monitor, CloudWatch alarm, Splunk search)
- [ ] Runbooks / README updated if operations change

## Plan review

<!-- The speculative plan is posted below by terraform-ci. Summarize anything
reviewers must look at (e.g. "1 resource replaced: CloudFront cache policy"). -->
