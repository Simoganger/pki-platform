# Runbook — Migrate from ADCS to AWS Private CA (Connector for AD)

Goal: retire the Windows Server ADCS enterprise CAs without interrupting Windows
auto-enrollment, and remove the ADCS attack surface (ESC1–ESC8, ESC15).

## Phase 0 — inventory (2–4 weeks)

- Templates actually used: on each CA, `certutil -view -restrict "NotAfter>now" -out "CertificateTemplate"` and count per template.
- Consumers per template: 802.1X / Wi-Fi, VPN, IIS, smart-card logon, code signing, S/MIME, appliances (SCEP/NDES).
- Security audit of current templates: `certipy find -vulnerable -enabled` or Locksmith; fix critical findings immediately, even before migration.
- Classify: **migrate** (computer / user authentication, server TLS), **replace** (TLS for AWS workloads → ACM; Kubernetes → cert-manager), **keep for now** (key archival, NDES/SCEP, enrollment agents, smart-card logon requiring specific NTAuth configuration).

## Phase 1 — trust

- Issuing CA `windows-issuing-g1` signed by the **existing root** (external signing), so
  no new root needs to be distributed to clients.
- When the connector is created, the CA certificate is published in AD and distributed to
  domain-joined machines' trust stores.

## Phase 2 — templates

- Recreate each migrated template as `awscc_pcaconnectorad_template` (see
  `environments/*/pki-core/connector-ad.tf`): subject built from AD, no requester-supplied
  subject, non-exportable keys, SID extension kept (strong mapping, KB5014754).
- Access control entries: `awscc_pcaconnectorad_template_group_access_control_entry`
  (Enroll / AutoEnroll) for the right AD groups.
- `superseded_templates`: list the old ADCS template names so holders re-enroll on the
  new template.

## Phase 3 — progressive switch

1. Pilot OU (IT computers) → 10 % → 50 % → 100 %, one week each, with success criteria:
   enrollment success rate, no authentication failures (802.1X, VPN logs).
2. On ADCS, unpublish each migrated template once its new version is validated.

## Phase 4 — decommission ADCS

1. ADCS issues nothing, but **keeps publishing its CRL** until its last certificate
   expires (or re-publish a final long CRL and stop the service, per CP).
2. Remove ADCS from NTAuth only after no authentication certificate from it remains valid.
3. Archive the CA database (audit), destroy keys per policy (HSM zeroization with minutes).
