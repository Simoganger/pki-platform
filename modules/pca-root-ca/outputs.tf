output "arn" {
  description = "ARN of the root CA."
  value       = aws_acmpca_certificate_authority.this.arn
}

output "id" {
  description = "ID of the root CA (last part of the ARN; also the CRL object name)."
  value       = element(split("/", aws_acmpca_certificate_authority.this.arn), 1)
}

output "certificate_pem" {
  description = "Root certificate (PEM). Distribute it to trust stores (GPO, MDM, base images, Java cacerts...)."
  value       = aws_acmpca_certificate.this.certificate
}

output "key_algorithm" {
  description = "Key algorithm of the root (children must sign with a matching signing algorithm family)."
  value       = var.key_algorithm
}

output "signing_algorithm" {
  description = "Signing algorithm the root uses when signing subordinate CAs."
  value       = var.signing_algorithm
}

output "certificate_authority_certificate_id" {
  description = "Dependency handle: reference it to make sure the CA is ACTIVE before issuing."
  value       = aws_acmpca_certificate_authority_certificate.this.id
}
