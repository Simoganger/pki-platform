# Unit tests for the issuing CA module (mocked AWS provider).

mock_provider "aws" {
  mock_data "aws_partition" {
    defaults = {
      partition = "aws"
    }
  }

  mock_data "aws_caller_identity" {
    defaults = {
      account_id = "111111111111"
    }
  }

  # Mocked values must still pass the provider's ARN validation.
  mock_resource "aws_acmpca_certificate_authority" {
    defaults = {
      arn = "arn:aws:acm-pca:ca-central-1:111111111111:certificate-authority/bbbbbbbb-0000-0000-0000-000000000000"
    }
  }
}

variables {
  name  = "servers-issuing-g1"
  usage = "tls-server"
  subject = {
    common_name  = "Example Internal Servers Issuing CA G1"
    organization = "Example Bank"
  }
  crl = {
    s3_bucket_name = "example-pki-crl"
    custom_cname   = "crl.pki.example.com"
  }
}

run "pca_mode_signs_with_parent" {
  command = plan

  variables {
    signing_mode             = "PCA"
    parent_ca_arn            = "arn:aws:acm-pca:ca-central-1:111111111111:certificate-authority/aaaaaaaa-0000-0000-0000-000000000000"
    parent_signing_algorithm = "SHA512WITHRSA"
  }

  assert {
    condition     = length(aws_acmpca_certificate.signed_by_pca_parent) == 1
    error_message = "PCA mode must create the signing request to the parent."
  }

  assert {
    condition     = aws_acmpca_certificate.signed_by_pca_parent[0].template_arn == "arn:aws:acm-pca:::template/SubordinateCACertificate_PathLen0/V1"
    error_message = "Issuing CAs must use a PathLen0 template."
  }

  assert {
    condition     = length(aws_acmpca_permission.acm) == 1
    error_message = "ACM managed renewal permission should be granted by default."
  }
}

run "external_mode_phase1_waits_for_ceremony" {
  command = plan

  variables {
    signing_mode = "EXTERNAL"
  }

  assert {
    condition     = length(aws_acmpca_certificate.signed_by_pca_parent) == 0 && length(aws_acmpca_certificate_authority_certificate.external) == 0
    error_message = "Phase 1 must only create the CA (PENDING_CERTIFICATE)."
  }
}

run "name_constraints_switch_to_passthrough_template" {
  command = plan

  variables {
    signing_mode                = "PCA"
    parent_ca_arn               = "arn:aws:acm-pca:ca-central-1:111111111111:certificate-authority/aaaaaaaa-0000-0000-0000-000000000000"
    parent_signing_algorithm    = "SHA512WITHRSA"
    name_constraints_der_base64 = "MBugGTAXghUuaW50ZXJuYWwuZXhhbXBsZS5jb20="
  }

  assert {
    condition     = endswith(aws_acmpca_certificate.signed_by_pca_parent[0].template_arn, "BlankSubordinateCACertificate_PathLen0_APIPassthrough/V1")
    error_message = "Name constraints require the APIPassthrough template."
  }
}

run "unknown_usage_is_rejected" {
  command = plan

  variables {
    usage        = "everything"
    signing_mode = "EXTERNAL" # isolate the failure to the variable validation
  }

  expect_failures = [var.usage]
}
