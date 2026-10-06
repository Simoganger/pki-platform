output "delivery_stream_arn" {
  description = "Firehose stream ARN."
  value       = aws_kinesis_firehose_delivery_stream.splunk.arn
}

output "backup_bucket_name" {
  description = "Failed-events bucket (replay with the Splunk add-on or a Firehose re-ingest)."
  value       = aws_s3_bucket.backup.id
}
