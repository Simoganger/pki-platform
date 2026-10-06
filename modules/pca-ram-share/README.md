# Module `pca-ram-share`

```text
Shares one or more issuing CAs with other AWS accounts / OUs through AWS
Resource Access Manager. Consumer accounts can then ISSUE certificates
(directly or through ACM) but can never administer, disable or delete the CA.

This is the "vending machine" distribution mechanism: the PKI account owns
the CAs; workload accounts consume them.

RAM managed permissions for AWS Private CA (pick the narrowest):
  AWSRAMDefaultPermissionCertificateAuthority        -> end-entity certs (default)
  AWSRAMBlankEndEntityCertificateAPICSRPassthroughIssuanceCertificateAuthority
  AWSRAMSubordinateCACertificatePathLen0IssuanceCertificateAuthority (lets the
    consumer create subordinate CAs - almost never what you want)
```

Usage examples: the root modules in `environments/` and the cookbook in the root [README](../../README.md).

## Inputs

| Name | Description | Type | Required |
| --- | --- | --- | --- |
| `name` | Name of the RAM resource share. | `string` | **yes** |
| `certificate_authority_arns` | Issuing CA ARNs to share. Never share a root CA. | `list(string)` | **yes** |
| `principals` | Organization OU ARNs (arn:aws:organizations::<mgmt>:ou/o-xxx/ou-xxx) or 12-digit account IDs. | `list(string)` | **yes** |
| `permission_arns` | RAM managed permission ARNs. Empty = AWSRAMDefaultPermissionCertificateAuthority. | `list(string)` | no |
| `tags` | Tags. | `map(string)` | no |

## Outputs

| Name | Description |
| --- | --- |
| `resource_share_arn` | ARN of the RAM share. |
