output "plan_role_arn" {
  description = "Set as TFC_AWS_PLAN_ROLE_ARN on the workspaces."
  value       = aws_iam_role.plan.arn
}

output "apply_role_arn" {
  description = "Set as TFC_AWS_APPLY_ROLE_ARN on the workspaces."
  value       = aws_iam_role.apply.arn
}

output "github_inventory_role_arn" {
  description = "Set as repository variable AWS_INVENTORY_ROLE_ARN_<ENV> in GitHub."
  value       = try(aws_iam_role.github_inventory[0].arn, null)
}
