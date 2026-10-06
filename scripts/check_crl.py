#!/usr/bin/env python3
"""Inspect a CRL the way a relying party does - your first tool in a CRL incident.

  python scripts/check_crl.py http://crl.pki.example.com/crl/<ca-id>.crl
  python scripts/check_crl.py ./downloaded.crl --issuer-cert issuing-ca.pem --serial 0x1a2b

Shows issuer, thisUpdate, nextUpdate, time left, CRL number, number of revoked
entries, verifies the signature against the issuer certificate, and optionally
tells whether a given serial number is revoked (and why).
Exit code 2 if the CRL is expired or its signature is invalid.
"""

from __future__ import annotations

import argparse
import sys
import urllib.request
from datetime import datetime, timezone

from cryptography import x509


def load(source: str) -> bytes:
    if source.startswith(("http://", "https://")):
        with urllib.request.urlopen(source, timeout=15) as resp:  # noqa: S310
            return resp.read()
    with open(source, "rb") as fh:
        return fh.read()


def parse(data: bytes) -> x509.CertificateRevocationList:
    if data.lstrip().startswith(b"-----BEGIN"):
        return x509.load_pem_x509_crl(data)
    return x509.load_der_x509_crl(data)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("source", help="CRL URL or file (DER or PEM)")
    parser.add_argument("--issuer-cert", help="PEM certificate of the issuing CA, to verify the CRL signature")
    parser.add_argument("--serial", help="certificate serial number to look up (hex 0x.. or decimal)")
    args = parser.parse_args(argv)

    crl = parse(load(args.source))
    now = datetime.now(timezone.utc)
    next_update = crl.next_update_utc
    hours_left = (next_update - now).total_seconds() / 3600 if next_update else None

    try:
        crl_number = crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
    except x509.ExtensionNotFound:
        crl_number = None

    print(f"Issuer        : {crl.issuer.rfc4514_string()}")
    print(f"thisUpdate    : {crl.last_update_utc.isoformat()}")
    print(f"nextUpdate    : {next_update.isoformat() if next_update else 'ABSENT'}")
    print(f"Time left     : {hours_left:.1f} h" if hours_left is not None else "Time left     : n/a")
    print(f"CRL number    : {crl_number}")
    print(f"Revoked certs : {len(crl)}")

    exit_code = 0
    if hours_left is not None and hours_left < 0:
        print("STATUS        : EXPIRED - hard-fail clients reject every certificate of this CA")
        exit_code = 2

    if args.issuer_cert:
        with open(args.issuer_cert, "rb") as fh:
            issuer = x509.load_pem_x509_certificate(fh.read())
        valid = crl.is_signature_valid(issuer.public_key())
        print(f"Signature     : {'VALID' if valid else 'INVALID'}")
        if not valid:
            exit_code = 2

    if args.serial:
        serial = int(args.serial, 16) if args.serial.lower().startswith("0x") else int(args.serial)
        entry = crl.get_revoked_certificate_by_serial_number(serial)
        if entry is None:
            print(f"Serial {args.serial}: NOT revoked")
        else:
            try:
                reason = entry.extensions.get_extension_for_class(x509.CRLReason).value.reason.name
            except x509.ExtensionNotFound:
                reason = "unspecified"
            print(f"Serial {args.serial}: REVOKED on {entry.revocation_date_utc.isoformat()} (reason: {reason})")

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
