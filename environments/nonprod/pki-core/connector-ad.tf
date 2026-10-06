###############################################################################
# AWS Private CA Connector for Active Directory (optional)
#
# Replaces ADCS enterprise CAs for Windows auto-enrollment: domain-joined
# computers and users keep enrolling through GPO exactly as before, but the
# certificates are signed by the windows issuing CA in AWS Private CA (no ADCS
# server to patch, no ESC1-ESC8 attack surface on a Windows CA).
#
# NOTE: these resources come from the AWS Cloud Control provider (awscc); the
# classic hashicorp/aws provider does not expose Connector for AD.
#
# Prerequisites: AWS Managed Microsoft AD, or AD Connector to the on-prem
# forest; a security group allowing the connector to reach the domain
# controllers (LDAP/Kerberos). Migration procedure:
# docs/runbooks/adcs-to-pca-migration.md
###############################################################################

locals {
  connector_enabled = var.connector_ad.enabled
}

resource "awscc_pcaconnectorad_directory_registration" "this" {
  count        = local.connector_enabled ? 1 : 0
  directory_id = var.connector_ad.directory_id
  tags         = local.default_tags
}

resource "awscc_pcaconnectorad_connector" "this" {
  count = local.connector_enabled ? 1 : 0

  certificate_authority_arn = module.issuing_ca[var.connector_ad.issuing_ca_key].arn
  directory_id              = var.connector_ad.directory_id

  vpc_information = {
    security_group_ids = var.connector_ad.security_group_ids
  }

  tags = local.default_tags

  depends_on = [awscc_pcaconnectorad_directory_registration.this]
}

resource "awscc_pcaconnectorad_service_principal_name" "this" {
  count = local.connector_enabled ? 1 : 0

  connector_arn              = awscc_pcaconnectorad_connector.this[0].connector_arn
  directory_registration_arn = awscc_pcaconnectorad_directory_registration.this[0].directory_registration_arn
}

###############################################################################
# Certificate template: computer authentication (replaces the ADCS "Computer"
# / "Workstation Authentication" templates). Hardened against ESC1: the subject
# is BUILT FROM ACTIVE DIRECTORY (require_dns_as_cn / san_require_dns), the
# requester can never supply it.
###############################################################################
resource "awscc_pcaconnectorad_template" "computer_auth" {
  count = local.connector_enabled ? 1 : 0

  connector_arn = awscc_pcaconnectorad_connector.this[0].connector_arn
  name          = "PKI-ComputerAuthentication-v1"

  definition = {
    template_v2 = {
      certificate_validity = {
        validity_period = { period = 1, period_type = "YEARS" }
        renewal_period  = { period = 6, period_type = "WEEKS" }
      }

      general_flags = {
        auto_enrollment = true
        machine_type    = true
      }

      enrollment_flags = {
        include_symmetric_algorithms                     = false
        no_security_extension                            = false # keep the SID extension (strong mapping, KB5014754)
        remove_invalid_certificate_from_personal_store   = true
        user_interaction_required                        = false
        enable_key_reuse_on_nt_token_keyset_storage_full = false
      }

      subject_name_flags = {
        require_dns_as_cn = true
        san_require_dns   = true
      }

      private_key_attributes = {
        key_spec           = "KEY_EXCHANGE"
        minimal_key_length = 2048
        crypto_providers   = ["Microsoft Software Key Storage Provider"]
      }

      private_key_flags = {
        client_version                 = "WINDOWS_SERVER_2012_R2"
        exportable_key                 = false
        strong_key_protection_required = false
      }

      extensions = {
        key_usage = {
          critical = true
          usage_flags = {
            digital_signature = true
            key_encipherment  = true
          }
        }
        application_policies = {
          critical = false
          policies = [
            { policy_object_identifier = "1.3.6.1.5.5.7.3.2" }, # client authentication
            { policy_object_identifier = "1.3.6.1.5.5.7.3.1" }, # server authentication
          ]
        }
      }

      # ADCS templates this one replaces: clients holding them re-enroll here.
      superseded_templates = var.connector_ad.superseded_adcs_templates
    }
  }

  tags = local.default_tags
}

# Who may enroll / auto-enroll (equivalent of the ADCS template security tab).
resource "awscc_pcaconnectorad_template_group_access_control_entry" "domain_computers" {
  count = local.connector_enabled && var.connector_ad.enroll_group_sid != null ? 1 : 0

  template_arn              = awscc_pcaconnectorad_template.computer_auth[0].template_arn
  group_display_name        = var.connector_ad.enroll_group_name
  group_security_identifier = var.connector_ad.enroll_group_sid

  access_rights = {
    enroll      = "ALLOW"
    auto_enroll = "ALLOW"
  }
}
