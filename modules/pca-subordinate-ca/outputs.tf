output "arn" {
  description = "ARN of the issuing CA. Pass it to ACM (certificate_authority_arn) or to RAM shares."
  value       = aws_acmpca_certificate_authority.this.arn
}

output "id" {
  description = "CA ID (CRL object name: crl/<id>.crl)."
  value       = element(split("/", aws_acmpca_certificate_authority.this.arn), 1)
}

output "csr_pem" {
  description = "CSR of the CA. In EXTERNAL mode, hand it to the key ceremony to be signed by the offline root."
  value       = aws_acmpca_certificate_authority.this.certificate_signing_request
}

output "certificate_pem" {
  description = "Installed CA certificate (null until installed)."
  value = try(
    aws_acmpca_certificate.signed_by_pca_parent[0].certificate,
    var.external_signed_certificate.certificate_pem,
    null
  )
}

output "status_hint" {
  description = "Human-readable state of the CA lifecycle."
  value = (
    var.signing_mode == "PCA" ? "ACTIVE (signed by AWS Private CA parent)" :
    var.external_signed_certificate == null ? "PENDING_CERTIFICATE - sign csr_pem in a key ceremony, then set external_signed_certificate" :
    "ACTIVE (signed by external offline root)"
  )
}

output "crl_url" {
  description = "Public CRL URL embedded in issued certificates (CDP)."
  value = var.crl.enabled ? (
    var.crl.custom_cname != null
    ? "http://${var.crl.custom_cname}/crl/${element(split("/", aws_acmpca_certificate_authority.this.arn), 1)}.crl"
    : "http://${var.crl.s3_bucket_name}.s3.amazonaws.com/crl/${element(split("/", aws_acmpca_certificate_authority.this.arn), 1)}.crl"
  ) : null
}

output "usage_mode" {
  description = "GENERAL_PURPOSE or SHORT_LIVED_CERTIFICATE."
  value       = var.usage_mode
}
