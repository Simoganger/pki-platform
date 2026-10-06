# Runbook — Key ceremony: sign an issuing CA CSR with the offline root

The production root CA key lives in an offline HSM (Thales Luna or Utimaco) and is only
used during a **key ceremony**: a scripted, witnessed, recorded procedure. This page is
the technical part; the bank's ceremony policy (roles, vault access, video, minutes)
always applies.

## Roles

| Role | Responsibility |
| --- | --- |
| Ceremony master | Runs the script, reads every step aloud |
| Witnesses (≥ 2) | Verify each step, sign the minutes |
| Key custodians (M of N) | Hold the HSM authentication parts (PED keys / smart cards) |
| Auditor (optional) | Independent observer |

## Before the ceremony

1. Phase 1 apply done: `terraform output -json issuing_ca_csrs` → save each CSR as
   `<ca-key>.csr` on removable media.
2. Check the CSR: `openssl req -in <ca-key>.csr -noout -text -verify` (subject and key
   algorithm must match the PR).
3. Prepare the extension section for the root signing config:

```ini
[v3_issuing_ca]
basicConstraints       = critical, CA:TRUE, pathlen:0
keyUsage               = critical, digitalSignature, keyCertSign, cRLSign
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always
crlDistributionPoints  = URI:http://crl.pki.example.com/root/example-bank-root-g1.crl
certificatePolicies    = 1.3.6.1.4.1.99999.1.1   # your CP OID
# Zone CAs only (output of scripts/build_name_constraints.py --format openssl):
# nameConstraints = critical, @name_constraints
```

## During the ceremony (offline signing workstation)

1. Verify tamper-evident seals of the HSM and workstation, record their numbers.
2. Custodians authenticate the HSM partition (M of N).
3. Sign with the HSM key through PKCS#11 (OpenSSL 3 + vendor provider/engine, or the
   vendor CA tool):

```bash
# OpenSSL 3 with the pkcs11 provider (or the vendor's provider) loaded:
openssl x509 -req -in servers-issuing-g1.csr \
  -provider pkcs11 -provider default \
  -CA root-ca.pem -CAkey "pkcs11:token=root-g1;object=root-g1-key;type=private" \
  -extfile v3_issuing_ca.cnf -extensions v3_issuing_ca \
  -days 1826 -sha384 -set_serial 0x$(openssl rand -hex 16) \
  -out servers-issuing-g1.pem
```

4. Verify: `openssl verify -CAfile root-ca.pem servers-issuing-g1.pem` and the checks in
   `environments/prod/pki-core/ceremony/README.md` (public key must match the CSR).
5. Log out the HSM, reseal, record seal numbers, sign the minutes.

## After the ceremony

1. PR adding `environments/prod/pki-core/ceremony/signed/<ca-key>.pem` and a minutes
   summary in `ceremony/minutes/`. Reviewers re-run the verification commands.
2. Merge → prod apply (with approval) installs the certificate; the CA becomes ACTIVE.

## Root CRL re-signing

Same ceremony, operation "generate CRL" with the root key (validity per CP, typically
6–12 months), publish to `http://crl.pki.example.com/root/...`. Schedule it at least 60
days before the current root CRL `nextUpdate`; the CRL checker watches it
(`offline_root_crl_url`).
