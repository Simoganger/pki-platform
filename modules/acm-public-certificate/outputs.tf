output "arn" {
  description = "ARN of the validated certificate."
  value       = aws_acm_certificate_validation.this.certificate_arn
}

output "not_after" {
  description = "Expiry of the current certificate."
  value       = aws_acm_certificate.this.not_after
}
