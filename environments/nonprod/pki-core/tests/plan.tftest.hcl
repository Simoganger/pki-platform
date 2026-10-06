# Whole-workspace plan test with mocked providers: catches wiring errors
# (unknown for_each keys, missing outputs, bad references) without AWS access.
#   cd environments/nonprod/pki-core && terraform init -backend=false && terraform test

mock_provider "aws" {
  mock_data "aws_partition" {
    defaults = { partition = "aws" }
  }
  mock_data "aws_caller_identity" {
    defaults = { account_id = "111111111111" }
  }
  mock_data "aws_region" {
    defaults = { region = "ca-central-1" }
  }
  mock_data "aws_iam_policy_document" {
    defaults = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
  }
  mock_resource "aws_acmpca_certificate_authority" {
    defaults = { arn = "arn:aws:acm-pca:ca-central-1:111111111111:certificate-authority/bbbbbbbb-0000-0000-0000-000000000000" }
  }
  mock_resource "aws_sns_topic" {
    defaults = { arn = "arn:aws:sns:ca-central-1:111111111111:pki-nonprod-alerts" }
  }
  mock_resource "aws_cloudwatch_log_group" {
    defaults = { arn = "arn:aws:logs:ca-central-1:111111111111:log-group:mock" }
  }
  mock_resource "aws_kms_key" {
    defaults = { arn = "arn:aws:kms:ca-central-1:111111111111:key/11111111-2222-3333-4444-555555555555" }
  }
  mock_resource "aws_iam_role" {
    defaults = { arn = "arn:aws:iam::111111111111:role/pki-mock" }
  }
  mock_resource "aws_sqs_queue" {
    defaults = { arn = "arn:aws:sqs:ca-central-1:111111111111:pki-mock" }
  }
  mock_resource "aws_lambda_function" {
    defaults = { arn = "arn:aws:lambda:ca-central-1:111111111111:function:pki-mock" }
  }
  mock_resource "aws_cloudwatch_event_rule" {
    defaults = { arn = "arn:aws:events:ca-central-1:111111111111:rule/pki-mock" }
  }
  mock_resource "aws_ssm_document" {
    defaults = { arn = "arn:aws:ssm:ca-central-1:111111111111:document/pki-mock" }
  }
  mock_resource "aws_s3_bucket" {
    defaults = { arn = "arn:aws:s3:::pki-nonprod-crl-111111111111", id = "pki-nonprod-crl-111111111111" }
  }
  mock_resource "aws_ram_resource_share" {
    defaults = { arn = "arn:aws:ram:ca-central-1:111111111111:resource-share/11111111-2222-3333-4444-555555555555" }
  }
  mock_resource "aws_cloudfront_distribution" {
    defaults = { arn = "arn:aws:cloudfront::111111111111:distribution/E123", domain_name = "d111.cloudfront.net" }
  }
}

mock_provider "aws" {
  alias = "us_east_1"
}

mock_provider "awscc" {}

mock_provider "archive" {}

variables {
  owner_email = "pki-team@example.com"
  issuing_cas = {
    servers-issuing-g1 = {
      usage        = "tls-server"
      common_name  = "Test Servers Issuing CA G1"
      ocsp_enabled = true
      share_with   = ["arn:aws:organizations::111111111111:ou/o-abc123/ou-abcd-11111111"]
    }
    workloads-mtls-g1 = {
      usage               = "mtls-workload"
      usage_mode          = "SHORT_LIVED_CERTIFICATE"
      common_name         = "Test Workloads mTLS CA G1"
      crl_expiration_days = 1
    }
  }
}

run "plan_whole_hierarchy" {
  command = plan

  assert {
    condition     = length(module.issuing_ca) == 2
    error_message = "Both issuing CAs must be planned."
  }

  assert {
    condition     = length(module.ram_share) == 1
    error_message = "Only CAs with share_with get a RAM share."
  }

  assert {
    condition     = length(module.issuing_ca["workloads-mtls-g1"].usage_mode) > 0 && module.issuing_ca["workloads-mtls-g1"].usage_mode == "SHORT_LIVED_CERTIFICATE"
    error_message = "Workloads CA must be short-lived."
  }
}
