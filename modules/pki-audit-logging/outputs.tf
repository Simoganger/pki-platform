output "trail_arn" {
  description = "CloudTrail trail ARN."
  value       = aws_cloudtrail.this.arn
}

output "trail_bucket_name" {
  description = "Bucket holding CloudTrail files."
  value       = aws_s3_bucket.trail.id
}

output "cloudwatch_log_group_name" {
  description = "Log group with CloudTrail events (Datadog can subscribe to it)."
  value       = aws_cloudwatch_log_group.trail.name
}

output "splunk_sqs_queue_url" {
  description = "Queue to configure in the Splunk Add-on for AWS (SQS-based S3 input)."
  value       = try(aws_sqs_queue.splunk[0].id, null)
}

output "splunk_reader_role_arn" {
  description = "Role the Splunk add-on assumes (with the external ID)."
  value       = try(aws_iam_role.splunk[0].arn, null)
}

output "kms_key_arn" {
  description = "KMS key encrypting the trail."
  value       = aws_kms_key.trail.arn
}
