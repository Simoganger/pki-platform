output "bucket_name" {
  description = "Name of the CRL bucket (pass to the CA modules as crl.s3_bucket_name)."
  value       = aws_s3_bucket.crl.id
}

output "bucket_arn" {
  description = "ARN of the CRL bucket."
  value       = aws_s3_bucket.crl.arn
}

output "distribution_domain_name" {
  description = "CloudFront domain name (use it as custom_cname if you have no alias yet)."
  value       = aws_cloudfront_distribution.crl.domain_name
}

output "distribution_id" {
  description = "CloudFront distribution ID (needed for cache invalidations)."
  value       = aws_cloudfront_distribution.crl.id
}

output "cdp_hostname" {
  description = "Hostname to use as custom_cname in the CA modules."
  value       = length(var.aliases) > 0 ? var.aliases[0] : aws_cloudfront_distribution.crl.domain_name
}
