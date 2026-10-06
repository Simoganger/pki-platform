output "lambda_function_name" {
  description = "Name of the distributor function (invoke manually for a first distribution: {\"certificateArn\": \"...\"})."
  value       = aws_lambda_function.this.function_name
}

output "secrets_kms_key_arn" {
  description = "KMS key protecting certificate secrets. Workload roles need kms:Decrypt on it."
  value       = aws_kms_key.secrets.arn
}

output "ssm_document_name" {
  description = "SSM document used to reload certificates on hosts."
  value       = aws_ssm_document.reload.name
}

output "dlq_url" {
  description = "Dead-letter queue (failed distributions)."
  value       = aws_sqs_queue.dlq.id
}
