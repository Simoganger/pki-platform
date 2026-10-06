#!/usr/bin/env bash
# Run from the relay host to validate SNMPv3 access to an HSM before enabling
# the Datadog check. Also proves that v1/v2c are DISABLED (must time out).
# Usage: ./test-snmpv3.sh <hsm-ip> <user>   (prompts for pass-phrases)
set -euo pipefail
HSM="$1"; USER_NAME="$2"
read -r -s -p "Auth pass-phrase: " AUTH; echo
read -r -s -p "Priv pass-phrase: " PRIV; echo

echo "== SNMPv3 authPriv (must succeed)"
snmpget -v3 -l authPriv -u "$USER_NAME" -a SHA-256 -A "$AUTH" -x AES -X "$PRIV" "$HSM" \
  1.3.6.1.2.1.1.1.0 1.3.6.1.2.1.1.3.0

echo "== SNMPv2c with 'public' (must FAIL / time out)"
if snmpget -v2c -c public -t 2 -r 0 "$HSM" 1.3.6.1.2.1.1.1.0 >/dev/null 2>&1; then
  echo "FAIL: SNMPv2c answered - disable v1/v2c on the HSM"; exit 1
else
  echo "OK: SNMPv2c disabled"
fi

echo "== SNMPv3 noAuthNoPriv (must FAIL)"
if snmpget -v3 -l noAuthNoPriv -u "$USER_NAME" -t 2 -r 0 "$HSM" 1.3.6.1.2.1.1.1.0 >/dev/null 2>&1; then
  echo "FAIL: unauthenticated SNMPv3 accepted"; exit 1
else
  echo "OK: unauthenticated access refused"
fi
