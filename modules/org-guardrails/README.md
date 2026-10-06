# Module `org-guardrails`

```text
Service Control Policy (SCP) enforcing the PKI operating model at the AWS
Organizations level. SCPs cannot be bypassed by any IAM policy inside a
member account (not even by account administrators).

  1. Only the PKI account(s) may create AWS Private CAs (no shadow PKI).
  2. Nobody can delete, disable or re-key a CA or change its trust settings
     except the HCP Terraform apply role and the break-glass role.
  3. Nobody can stop or delete CloudTrail in the PKI accounts.

Deploy from the Organizations management account (or a delegated admin).
TEST IN A SANDBOX OU FIRST: an SCP mistake can lock administrators out.
```

Usage examples: the root modules in `environments/` and the cookbook in the root [README](../../README.md).

## Inputs

| Name | Description | Type | Required |
| --- | --- | --- | --- |
| `policy_name` | SCP name. | `string` | no |
| `pki_account_ids` | Accounts allowed to create AWS Private CAs. | `list(string)` | **yes** |
| `privileged_role_arn_patterns` | Role ARN patterns allowed to perform trust-changing CA operations (HCP Terraform apply role, break-glass). | `list(string)` | **yes** |
| `target_ids` | Root, OU or account IDs the SCP is attached to. | `list(string)` | **yes** |
| `tags` | Tags. | `map(string)` | no |

## Outputs

| Name | Description |
| --- | --- |
| `policy_id` | SCP ID. |
