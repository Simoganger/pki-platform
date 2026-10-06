# Plan test for production: phase 1 of the external-root flow (no ceremony
# file yet) must create CAs in PENDING_CERTIFICATE state and share nothing.

mock_provider "aws" {
  mock_data "aws_partition" {
    defaults = { partition = "aws" }
  }
  mock_data "aws_caller_identity" {
    defaults = { account_id = "222222222222" }
  }
  mock_data "aws_region" {
    defaults = { region = "ca-central-1" }
  }
  mock_data "aws_iam_policy_document" {
    defaults = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
  }
  mock_resource "aws_acmpca_certificate_authority" {
    defaults = { arn = "arn:aws:acm-pca:ca-central-1:222222222222:certificate-authority/cccccccc-0000-0000-0000-000000000000" }
  }
  mock_resource "aws_sns_topic" {
    defaults = { arn = "arn:aws:sns:ca-central-1:222222222222:pki-prod-alerts" }
  }
  mock_resource "aws_cloudwatch_log_group" {
    defaults = { arn = "arn:aws:logs:ca-central-1:222222222222:log-group:mock" }
  }
  mock_resource "aws_kms_key" {
    defaults = { arn = "arn:aws:kms:ca-central-1:222222222222:key/11111111-2222-3333-4444-555555555555" }
  }
  mock_resource "aws_iam_role" {
    defaults = { arn = "arn:aws:iam::222222222222:role/pki-mock" }
  }
  mock_resource "aws_sqs_queue" {
    defaults = { arn = "arn:aws:sqs:ca-central-1:222222222222:pki-mock" }
  }
  mock_resource "aws_lambda_function" {
    defaults = { arn = "arn:aws:lambda:ca-central-1:222222222222:function:pki-mock" }
  }
  mock_resource "aws_cloudwatch_event_rule" {
    defaults = { arn = "arn:aws:events:ca-central-1:222222222222:rule/pki-mock" }
  }
  mock_resource "aws_ssm_document" {
    defaults = { arn = "arn:aws:ssm:ca-central-1:222222222222:document/pki-mock" }
  }
  mock_resource "aws_s3_bucket" {
    defaults = { arn = "arn:aws:s3:::pki-prod-crl-222222222222", id = "pki-prod-crl-222222222222" }
  }
  mock_resource "aws_cloudfront_distribution" {
    defaults = { arn = "arn:aws:cloudfront::222222222222:distribution/E222", domain_name = "d222.cloudfront.net" }
  }
}

mock_provider "aws" {
  alias = "us_east_1"
  mock_resource "aws_acm_certificate" {
    defaults = { arn = "arn:aws:acm:us-east-1:222222222222:certificate/11111111-2222-3333-4444-555555555555" }
  }
}

mock_provider "awscc" {}

mock_provider "archive" {}

variables {
  owner_email            = "pki-team@example.com"
  crl_hostname           = "crl.pki.example.com"
  public_route53_zone_id = "Z0123456789ABCDEFGHIJ"
  issuing_cas = {
    pci-issuing-g1 = {
      usage       = "pci"
      common_name = "Test PCI Issuing CA G1"
      share_with  = ["arn:aws:organizations::111111111111:ou/o-abc123/ou-abcd-44444444"]
    }
  }
}

run "phase1_pending_certificate" {
  command = plan

  assert {
    condition     = startswith(output.issuing_ca_status["pci-issuing-g1"], "PENDING_CERTIFICATE")
    error_message = "Without a ceremony file the CA must wait for signing."
  }

  assert {
    condition     = length(module.ram_share) == 0
    error_message = "A CA that is not ACTIVE must not be shared."
  }
}
