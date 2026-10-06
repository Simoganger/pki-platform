output "project_id" {
  description = "HCP Terraform project ID."
  value       = tfe_project.pki.id
}

output "workspace_ids" {
  description = "Workspace IDs by name."
  value       = { for k, ws in tfe_workspace.this : k => ws.id }
}

output "next_steps" {
  description = "Manual steps after bootstrap."
  value       = <<-EOT
    1. Create team tokens (Settings > Teams): pki-ci-plan and pki-ci-apply, with an expiry date.
    2. GitHub: repository secret TF_API_TOKEN_PLAN = pki-ci-plan token;
       environment secrets TF_API_TOKEN = pki-ci-apply token in environments "nonprod" and "production".
    3. GitHub: repository variables TF_CLOUD_ORGANIZATION = ${var.hcp_organization}, TF_CLOUD_HOSTNAME = ${var.hcp_hostname}.
    4. Add terraform variables (owner_email, issuing_cas...) to each workspace from terraform.tfvars.example.
  EOT
}
