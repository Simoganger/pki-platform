#!/usr/bin/env bash
# /usr/local/bin/pki-cert-sync.sh  - installed on workload hosts (EC2 or on-prem
# servers managed by SSM). Called by:
#   - the SSM document <prefix>-ReloadCertificate right after a renewal, and
#   - a systemd timer once a day (safety net if an SSM command was missed).
#
# It reads the certificate bundle written by the acm-renewal-distributor Lambda
# from Secrets Manager (instance role = pki:reader-role of the certificate),
# installs it atomically, validates it, and reloads the service only if the
# certificate actually changed.
#
# Requirements: aws CLI v2, jq, openssl. Configure via /etc/pki-cert-sync.conf:
#   CERT_DIR=/etc/pki/tls/app
#   SERVICE=nginx
#   OWNER=root:nginx
set -euo pipefail

SECRET_NAME="${1:?usage: pki-cert-sync.sh <secret-name>}"
CONF=/etc/pki-cert-sync.conf
CERT_DIR=/etc/pki/tls/app
SERVICE=nginx
OWNER=root:root
# shellcheck disable=SC1090
[[ -f "$CONF" ]] && source "$CONF"

log() { logger -t pki-cert-sync "$*"; echo "$*"; }

umask 077
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

aws secretsmanager get-secret-value --secret-id "$SECRET_NAME" \
  --query SecretString --output text > "$WORK/bundle.json"

jq -r '.certificate'        "$WORK/bundle.json" > "$WORK/cert.pem"
jq -r '.certificate_chain'  "$WORK/bundle.json" > "$WORK/chain.pem"
jq -r '.private_key'        "$WORK/bundle.json" > "$WORK/key.pem"
cat "$WORK/cert.pem" "$WORK/chain.pem" > "$WORK/fullchain.pem"

# Validate before touching anything live:
# 1. the key matches the certificate
if ! cmp -s <(openssl x509 -in "$WORK/cert.pem" -noout -pubkey) <(openssl pkey -in "$WORK/key.pem" -pubout); then
  log "ERROR: private key does not match certificate in $SECRET_NAME"; exit 1
fi
# 2. the certificate is currently valid for at least one day
if ! openssl x509 -in "$WORK/cert.pem" -noout -checkend 86400 >/dev/null; then
  log "ERROR: certificate in $SECRET_NAME expires within 24h"; exit 1
fi

NEW_FP="$(openssl x509 -in "$WORK/cert.pem" -noout -fingerprint -sha256)"
OLD_FP="$( [[ -f "$CERT_DIR/cert.pem" ]] && openssl x509 -in "$CERT_DIR/cert.pem" -noout -fingerprint -sha256 || echo none)"
if [[ "$NEW_FP" == "$OLD_FP" ]]; then
  log "Certificate unchanged ($NEW_FP), nothing to do"; exit 0
fi

install -d -m 0750 -o "${OWNER%%:*}" -g "${OWNER##*:}" "$CERT_DIR"
for f in cert.pem chain.pem fullchain.pem key.pem; do
  mode=0644; [[ "$f" == key.pem ]] && mode=0640
  install -m "$mode" -o "${OWNER%%:*}" -g "${OWNER##*:}" "$WORK/$f" "$CERT_DIR/$f.new"
  mv -f "$CERT_DIR/$f.new" "$CERT_DIR/$f"   # atomic replace
done

# Validate the service configuration before reloading (nginx example).
if [[ "$SERVICE" == nginx ]]; then nginx -t -q; fi
systemctl reload "$SERVICE"

log "Installed new certificate for $SECRET_NAME ($NEW_FP), $SERVICE reloaded"
