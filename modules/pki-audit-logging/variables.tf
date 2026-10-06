variable "trail_name" {
  description = "Name of the CloudTrail trail."
  type        = string
}

variable "bucket_name" {
  description = "Globally unique name of the trail bucket."
  type        = string
}

variable "is_organization_trail" {
  description = "true if deployed from the Organizations management / delegated admin account."
  type        = bool
  default     = false
}

variable "object_lock" {
  description = "S3 Object Lock (WORM). Can only be enabled at bucket creation."
  type = object({
    enabled = optional(bool, true)
    mode    = optional(string, "GOVERNANCE") # COMPLIANCE = even root cannot delete before expiry
    days    = optional(number, 365)
  })
  default = {}
}

variable "retention_days" {
  description = "Total retention of CloudTrail files in S3."
  type        = number
  default     = 2555 # 7 years, typical for banking records
}

variable "cloudwatch_retention_days" {
  description = "Retention in CloudWatch Logs (hot search for tripwires)."
  type        = number
  default     = 365 # PCI DSS 10.5.1: 12 months, 3 immediately available
}

variable "alerts_topic_arn" {
  description = "SNS topic receiving tripwire alarms (module pki-monitoring)."
  type        = string
}

variable "trusted_automation_role_name_patterns" {
  description = "IAM role NAMES (wildcards allowed) whose changes are expected (HCP Terraform apply role)."
  type        = list(string)
  default     = ["hcp-terraform-pki-apply*"]
}

variable "log_admin_role_arns" {
  description = "Role ARNs (wildcards allowed) allowed to delete trail objects / change lifecycle. Keep it to break-glass."
  type        = list(string)
}

variable "splunk" {
  description = "Splunk Add-on for AWS (SQS-based S3 input) integration."
  type = object({
    enabled              = optional(bool, false)
    reader_principal_arn = optional(string) # IAM role/user ARN used by the Splunk heavy forwarder / IDM
    external_id          = optional(string)
  })
  default = {}

  validation {
    condition     = !var.splunk.enabled || (var.splunk.reader_principal_arn != null && var.splunk.external_id != null)
    error_message = "splunk.reader_principal_arn and splunk.external_id are required when splunk.enabled = true."
  }
}

variable "access_log_bucket" {
  description = "Optional central S3 access-log bucket for the trail bucket."
  type        = string
  default     = null
}

variable "tags" {
  description = "Tags."
  type        = map(string)
  default     = {}
}
