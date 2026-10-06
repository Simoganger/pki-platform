variable "name_prefix" {
  description = "Prefix for resource names."
  type        = string
}

variable "hec_endpoint" {
  description = "Splunk HEC endpoint reachable by Firehose, e.g. https://http-inputs-firehose-<stack>.splunkcloud.com:443 or your on-prem HEC load balancer."
  type        = string

  validation {
    condition     = startswith(var.hec_endpoint, "https://")
    error_message = "hec_endpoint must use HTTPS."
  }
}

variable "hec_token_secret_arn" {
  description = "Secrets Manager secret ARN containing {\"hec_token\":\"...\"} (created outside Terraform so the token never reaches the state)."
  type        = string
}

variable "log_group_names" {
  description = "CloudWatch log groups to stream to Splunk."
  type        = list(string)
}

variable "backup_bucket_name" {
  description = "Bucket for events Splunk failed to accept."
  type        = string
}

variable "tags" {
  description = "Tags."
  type        = map(string)
  default     = {}
}
