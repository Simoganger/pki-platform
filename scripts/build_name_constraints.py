#!/usr/bin/env python3
"""Build an X.509 NameConstraints extension (RFC 5280 section 4.2.1.10).

Name constraints restrict which names a CA can sign: a client validating a
chain REJECTS any certificate whose DNS names fall outside the permitted
subtrees of any CA above it. It is the strongest technical control to stop an
issuing CA (or a stolen key) from impersonating, say, your public website.

Outputs:
  --format base64   value for the Terraform variable name_constraints_der_base64
                    (AWS Private CA APIPassthrough CustomExtensions)
  --format openssl  section to paste into the OpenSSL / HSM ceremony config used
                    when the OFFLINE root signs an issuing CA CSR

Examples:
  python scripts/build_name_constraints.py --permit .nonprod.internal.example.com
  python scripts/build_name_constraints.py --permit .pci.internal.example.com \
      --exclude .corp.example.com --format openssl
"""

from __future__ import annotations

import argparse
import base64
import sys

from cryptography import x509


def build(permitted: list[str], excluded: list[str]) -> x509.NameConstraints:
    if not permitted and not excluded:
        raise ValueError("at least one --permit or --exclude is required")
    for name in permitted + excluded:
        if "*" in name or "://" in name or " " in name:
            raise ValueError(f"invalid DNS constraint {name!r}: use a domain like .example.com")
    return x509.NameConstraints(
        permitted_subtrees=[x509.DNSName(n) for n in permitted] or None,
        excluded_subtrees=[x509.DNSName(n) for n in excluded] or None,
    )


def to_base64(nc: x509.NameConstraints) -> str:
    return base64.b64encode(nc.public_bytes()).decode()


def to_openssl(permitted: list[str], excluded: list[str]) -> str:
    lines = ["# Add to the [v3_issuing_ca] section of the ceremony openssl.cnf", "nameConstraints = critical, @name_constraints", "", "[name_constraints]"]
    lines += [f"permitted;DNS.{i} = {n.lstrip('.')}" for i, n in enumerate(permitted)]
    lines += [f"excluded;DNS.{i} = {n.lstrip('.')}" for i, n in enumerate(excluded)]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--permit", action="append", default=[], help="permitted DNS subtree (repeatable), e.g. .internal.example.com")
    parser.add_argument("--exclude", action="append", default=[], help="excluded DNS subtree (repeatable)")
    parser.add_argument("--format", choices=["base64", "openssl"], default="base64")
    args = parser.parse_args(argv)
    try:
        nc = build(args.permit, args.exclude)
    except ValueError as exc:
        parser.error(str(exc))
    print(to_base64(nc) if args.format == "base64" else to_openssl(args.permit, args.exclude))
    return 0


if __name__ == "__main__":
    sys.exit(main())
