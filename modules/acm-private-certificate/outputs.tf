output "arn" {
  description = "ACM certificate ARN (attach it to an ALB listener, API Gateway domain, etc.)."
  value       = aws_acm_certificate.this.arn
}

output "domain_name" {
  description = "Primary name."
  value       = aws_acm_certificate.this.domain_name
}

output "not_after" {
  description = "Expiry timestamp of the current certificate."
  value       = aws_acm_certificate.this.not_after
}

output "renewal_eligibility" {
  description = "ELIGIBLE means ACM will renew it automatically."
  value       = aws_acm_certificate.this.renewal_eligibility
}

output "secret_name" {
  description = "Secrets Manager secret receiving the exported certificate (if distribution is enabled)."
  value       = try(local.distribution_tags["pki:secret-name"], null)
}
