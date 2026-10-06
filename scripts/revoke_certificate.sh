#!/usr/bin/env bash
# Revoke a certificate issued by AWS Private CA - with guardrails.
#
# Revocation is irreversible (except reason CERTIFICATE_HOLD, which AWS Private
# CA does not support). This wrapper:
#   - shows the certificate before revoking it (subject, SAN, expiry);
#   - forces an explicit RFC 5280 reason and a change/incident ticket;
#   - requires typing the serial number again to confirm;
#   - prints the follow-up steps (CRL refresh, CloudFront, consumers).
#
# Usage:
#   scripts/revoke_certificate.sh <ca-arn> <certificate-arn> <reason> <ticket>
#
# Reasons: KEY_COMPROMISE | CERTIFICATE_AUTHORITY_COMPROMISE | AFFILIATION_CHANGED |
#          SUPERSEDED | CESSATION_OF_OPERATION | PRIVILEGE_WITHDRAWN | UNSPECIFIED |
#          A_A_COMPROMISE
set -euo pipefail

if [[ $# -ne 4 ]]; then
  sed -n '2,20p' "$0"
  exit 1
fi

CA_ARN="$1"
CERT_ARN="$2"
REASON="$3"
TICKET="$4"
REGION="$(cut -d: -f4 <<<"$CA_ARN")"

case "$REASON" in
  KEY_COMPROMISE|CERTIFICATE_AUTHORITY_COMPROMISE|AFFILIATION_CHANGED|SUPERSEDED|CESSATION_OF_OPERATION|PRIVILEGE_WITHDRAWN|UNSPECIFIED|A_A_COMPROMISE) ;;
  *) echo "Invalid reason: $REASON" >&2; exit 1 ;;
esac

if [[ ! "$TICKET" =~ ^(CHG|INC|SEC)[0-9]+$ ]]; then
  echo "Ticket must look like CHG123456, INC123456 or SEC123456" >&2
  exit 1
fi

PEM="$(aws acm-pca get-certificate --region "$REGION" \
  --certificate-authority-arn "$CA_ARN" --certificate-arn "$CERT_ARN" \
  --query Certificate --output text)"

SERIAL_HEX="$(openssl x509 -noout -serial <<<"$PEM" | cut -d= -f2)"
# AWS expects the serial as colon-separated hex pairs, lower case.
SERIAL="$(sed 's/../&:/g; s/:$//' <<<"$SERIAL_HEX" | tr 'A-F' 'a-f')"

echo "------------------------------------------------------------------"
openssl x509 -noout -subject -issuer -dates -ext subjectAltName <<<"$PEM"
echo "Serial : $SERIAL"
echo "Reason : $REASON"
echo "Ticket : $TICKET"
echo "------------------------------------------------------------------"
read -r -p "Type the serial number to confirm revocation: " CONFIRM
if [[ "$CONFIRM" != "$SERIAL" ]]; then
  echo "Confirmation does not match. Nothing revoked." >&2
  exit 1
fi

aws acm-pca revoke-certificate --region "$REGION" \
  --certificate-authority-arn "$CA_ARN" \
  --certificate-serial "$SERIAL" \
  --revocation-reason "$REASON"

echo "Revoked. Logged in CloudTrail (RevokeCertificate) and raised to the PKI alert topic."
cat <<EOF

Follow-up:
  1. The serial appears in the next CRL (AWS Private CA regenerates it within
     about 30 minutes) and in OCSP almost immediately.
  2. Shorten client caching if urgent: invalidate CloudFront for /crl/*
       aws cloudfront create-invalidation --distribution-id <id> --paths '/crl/*'
  3. Check: python scripts/check_crl.py <crl-url> --serial 0x$SERIAL_HEX
  4. Make sure the workload received a replacement certificate.
  5. Record the revocation in ticket $TICKET.
EOF
