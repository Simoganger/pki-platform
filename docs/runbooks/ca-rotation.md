# Runbook — Planned issuing CA rotation

**When**: the inventory reports an issuing CA with less than 540 days (18 months) left,
an algorithm change (e.g. move to ECC or ML-DSA), or a policy change.

Rule: a CA must never issue a certificate that outlives it. With 13-month ACM
certificates, a CA must stop issuing at least 13 months before its own expiry.

## Phase 1 — create the new generation (month 0)

1. PR: add `servers-issuing-g2` next to `servers-issuing-g1` in `issuing_cas` (new key,
   same usage, same `share_with`). Never "renew" a CA with the same key.
2. Prod: two-phase signing with a key ceremony (`external-root-signing.md`).
3. Add the new CRL URL to monitoring (automatic for CAs in `issuing_cas`).

## Phase 2 — move consumers (months 1–4)

1. Publish the new CA ARN to teams; update their module calls (`certificate_authority_arn`).
   ACM issues new certificates, `create_before_destroy` keeps listeners valid.
2. Clients that pin intermediate certificates must receive the new intermediate first.
3. Track progress with the inventory (`issuer_or_usage` column).

## Phase 3 — stop issuance on the old CA (when no consumer is left)

1. Remove `g1` from RAM shares.
2. Set `enabled = false` on `g1`: it can no longer issue, but **keeps publishing its CRL**.

## Phase 4 — retire (after the last g1 certificate expires)

1. Verify with a PCA audit report that no unexpired certificate remains.
2. Break-glass deletion (outside the pipeline, which cannot delete CAs), with ticket:
   `aws acm-pca delete-certificate-authority --permanent-deletion-time-in-days 30`.
3. Remove `g1` from `issuing_cas` **together with** a `removed` block in the same PR, so
   Terraform forgets the (already deleted) CA instead of planning a destroy that
   Sentinel would block:

   ```hcl
   removed {
     from = module.issuing_ca["servers-issuing-g1"]
     lifecycle {
       destroy = false
     }
   }
   ```
