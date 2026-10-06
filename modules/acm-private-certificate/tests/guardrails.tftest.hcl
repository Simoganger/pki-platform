# Unit tests: run with `terraform test` inside modules/acm-private-certificate.
# No AWS credentials needed - the AWS provider is mocked.

mock_provider "aws" {}

variables {
  certificate_authority_arn = "arn:aws:acm-pca:ca-central-1:111111111111:certificate-authority/11111111-2222-3333-4444-555555555555"
  allowed_domain_suffixes   = [".internal.example.com"]
  owner                     = "team-payments@example.com"
  application               = "APP-1234"
}

run "allowed_name_plans" {
  command = plan

  variables {
    domain_name               = "payments-api.internal.example.com"
    subject_alternative_names = ["payments-api-v2.internal.example.com"]
  }

  assert {
    condition     = aws_acm_certificate.this.tags["pki:owner"] == "team-payments@example.com"
    error_message = "Owner tag must be set."
  }

  assert {
    condition     = aws_acm_certificate.this.key_algorithm == "EC_prime256v1"
    error_message = "Default key algorithm should be ECDSA P-256."
  }
}

run "lookalike_domain_is_rejected" {
  command = plan

  variables {
    domain_name = "payments.evilinternal.example.com.attacker.net"
  }

  expect_failures = [aws_acm_certificate.this]
}

run "suffix_trick_is_rejected" {
  command = plan

  variables {
    domain_name = "evilinternal.example.com"
  }

  expect_failures = [aws_acm_certificate.this]
}

run "wildcard_needs_exception" {
  command = plan

  variables {
    domain_name = "*.internal.example.com"
  }

  expect_failures = [aws_acm_certificate.this]
}

run "wildcard_with_exception_plans" {
  command = plan

  variables {
    domain_name    = "*.internal.example.com"
    allow_wildcard = true
  }
}

run "invalid_ca_arn_is_rejected" {
  command = plan

  variables {
    domain_name               = "x.internal.example.com"
    certificate_authority_arn = "arn:aws:acm:ca-central-1:111111111111:certificate/abc"
  }

  expect_failures = [var.certificate_authority_arn]
}
