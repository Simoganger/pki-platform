###############################################################################
# Module: org-guardrails
#
# Service Control Policy (SCP) enforcing the PKI operating model at the AWS
# Organizations level. SCPs cannot be bypassed by any IAM policy inside a
# member account (not even by account administrators).
#
#   1. Only the PKI account(s) may create AWS Private CAs (no shadow PKI).
#   2. Nobody can delete, disable or re-key a CA or change its trust settings
#      except the HCP Terraform apply role and the break-glass role.
#   3. Nobody can stop or delete CloudTrail in the PKI accounts.
#
# Deploy from the Organizations management account (or a delegated admin).
# TEST IN A SANDBOX OU FIRST: an SCP mistake can lock administrators out.
###############################################################################

data "aws_iam_policy_document" "scp" {
  statement {
    sid       = "DenyCACreationOutsidePKIAccounts"
    effect    = "Deny"
    actions   = ["acm-pca:CreateCertificateAuthority"]
    resources = ["*"]
    condition {
      test     = "StringNotEquals"
      variable = "aws:PrincipalAccount"
      values   = var.pki_account_ids
    }
  }

  statement {
    sid    = "DenyCATrustChangesExceptPipelineAndBreakGlass"
    effect = "Deny"
    actions = [
      "acm-pca:DeleteCertificateAuthority",
      "acm-pca:UpdateCertificateAuthority",
      "acm-pca:ImportCertificateAuthorityCertificate",
      "acm-pca:RestoreCertificateAuthority",
      "acm-pca:CreatePermission",
      "acm-pca:DeletePermission",
      "acm-pca:PutPolicy",
      "acm-pca:DeletePolicy",
    ]
    resources = ["*"]
    condition {
      test     = "ArnNotLike"
      variable = "aws:PrincipalArn"
      values   = var.privileged_role_arn_patterns
    }
  }

  statement {
    sid       = "DenyAuditTrailTampering"
    effect    = "Deny"
    actions   = ["cloudtrail:StopLogging", "cloudtrail:DeleteTrail", "cloudtrail:UpdateTrail", "cloudtrail:PutEventSelectors"]
    resources = ["*"]
    condition {
      test     = "ArnNotLike"
      variable = "aws:PrincipalArn"
      values   = var.privileged_role_arn_patterns
    }
  }

  statement {
    sid       = "DenyRAMExternalSharing"
    effect    = "Deny"
    actions   = ["ram:CreateResourceShare", "ram:UpdateResourceShare"]
    resources = ["*"]
    condition {
      test     = "Bool"
      variable = "ram:RequestedAllowsExternalPrincipals"
      values   = ["true"]
    }
  }
}

resource "aws_organizations_policy" "pki" {
  name        = var.policy_name
  description = "PKI guardrails: no shadow CAs, no out-of-band trust changes, no audit tampering"
  type        = "SERVICE_CONTROL_POLICY"
  content     = data.aws_iam_policy_document.scp.json
  tags        = var.tags
}

resource "aws_organizations_policy_attachment" "pki" {
  for_each  = toset(var.target_ids)
  policy_id = aws_organizations_policy.pki.id
  target_id = each.value
}
