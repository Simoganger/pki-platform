# Runbook — Rotating platform secrets

| Secret | Rotation | Procedure |
| --- | --- | --- |
| HCP team token `pki-ci-plan` | 90 days | HCP: Settings → Teams → pki-ci-plan → regenerate token (with expiry) → GitHub repository secret `TF_API_TOKEN_PLAN` → re-run a PR check |
| HCP team token `pki-ci-apply` | 90 days | Regenerate → update secret `TF_API_TOKEN` in environments `nonprod`, `production-plan`, `production` → `workflow_dispatch` on `terraform-deploy` (nonprod) to verify |
| Datadog API / APP keys | per Datadog policy | Create new keys (APP key scoped to monitors/synthetics/dashboards) → `bootstrap/hcp-terraform` apply with new `TF_VAR_datadog_*` → revoke old keys |
| Splunk HEC token | per Splunk policy | New token in Splunk → `aws secretsmanager put-secret-value --secret-id <arn> --secret-string '{"hec_token":"..."}'` → check Firehose delivery metrics → disable old token |
| Splunk add-on external ID | yearly | Update workspace variable `splunk.external_id` and the add-on account config the same day |
| SNMPv3 pass-phrases | quarterly | Create new USM user on the HSM → update `pki/snmp/*` secrets → restart Agent → `test-snmpv3.sh` → delete old USM user |
| Exported certificate keys | at every renewal (automatic) | Nothing to do; a manual re-export rotates nothing, re-issue the certificate instead |

Never rotate by putting a secret in a file of this repository, in a PR description or in
a Terraform variable file. Team tokens and keys are entered only in the HCP / GitHub UIs
or via environment variables.
