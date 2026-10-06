#!/usr/bin/env python3
"""Certificate and CA inventory for one AWS account (one or more regions).

What it reports
  - every ACM certificate (public, private, imported): names, issuer type,
    expiry, days left, renewal eligibility, in-use resources, owner tag;
  - every AWS Private CA: type, status, usage mode, key algorithm, CA
    certificate expiry and days left.

Uses
  - daily GitHub Actions job (.github/workflows/cert-inventory.yml) that fails
    and opens an issue when something expires within --threshold-days;
  - evidence for PCI DSS 4.0.1 req. 4.2.1.1 (inventory of trusted keys and
    certificates) and 12.3.3 (cryptographic inventory);
  - quick answers during an incident ("which certs are issued by CA X?").

Exit codes: 0 = all good, 2 = at least one item under the threshold, 1 = error.

  python scripts/cert_inventory.py --regions ca-central-1 us-east-1 \
      --threshold-days 30 --format csv --output inventory.csv
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import sys
from datetime import datetime, timezone
from typing import Iterable

FIELDS = [
    "kind", "region", "name", "arn", "type", "status", "issuer_or_usage", "key_algorithm",
    "not_after", "days_left", "renewal_eligibility", "in_use_by", "owner",
]


def _days_left(not_after: datetime | None, now: datetime) -> int | None:
    if not_after is None:
        return None
    return int((not_after - now).total_seconds() // 86400)


def acm_rows(acm, region: str, now: datetime) -> Iterable[dict]:
    paginator = acm.get_paginator("list_certificates")
    statuses = ["ISSUED", "PENDING_VALIDATION", "INACTIVE", "EXPIRED", "FAILED"]
    for page in paginator.paginate(CertificateStatuses=statuses, Includes={"keyTypes": ["RSA_1024", "RSA_2048", "RSA_3072", "RSA_4096", "EC_prime256v1", "EC_secp384r1", "EC_secp521r1"]}):
        for summary in page["CertificateSummaryList"]:
            arn = summary["CertificateArn"]
            cert = acm.describe_certificate(CertificateArn=arn)["Certificate"]
            tags = {t["Key"]: t.get("Value", "") for t in acm.list_tags_for_certificate(CertificateArn=arn).get("Tags", [])}
            not_after = cert.get("NotAfter")
            yield {
                "kind": "certificate",
                "region": region,
                "name": cert.get("DomainName"),
                "arn": arn,
                "type": cert.get("Type"),  # AMAZON_ISSUED | PRIVATE | IMPORTED
                "status": cert.get("Status"),
                "issuer_or_usage": cert.get("CertificateAuthorityArn") or cert.get("Issuer", ""),
                "key_algorithm": cert.get("KeyAlgorithm"),
                "not_after": not_after.isoformat() if not_after else "",
                "days_left": _days_left(not_after, now),
                "renewal_eligibility": cert.get("RenewalEligibility", ""),
                "in_use_by": ";".join(cert.get("InUseBy", [])),
                "owner": tags.get("pki:owner", tags.get("owner", "")),
            }


def pca_rows(pca, region: str, now: datetime) -> Iterable[dict]:
    from cryptography import x509

    paginator = pca.get_paginator("list_certificate_authorities")
    for page in paginator.paginate():
        for ca in page["CertificateAuthorities"]:
            arn = ca["Arn"]
            not_after = ca.get("NotAfter")
            if not_after is None and ca.get("Status") == "ACTIVE":
                pem = pca.get_certificate_authority_certificate(CertificateAuthorityArn=arn)["Certificate"]
                not_after = x509.load_pem_x509_certificate(pem.encode()).not_valid_after_utc
            config = ca.get("CertificateAuthorityConfiguration", {})
            yield {
                "kind": "certificate-authority",
                "region": region,
                "name": config.get("Subject", {}).get("CommonName", ""),
                "arn": arn,
                "type": ca.get("Type"),
                "status": ca.get("Status"),
                "issuer_or_usage": ca.get("UsageMode", ""),
                "key_algorithm": config.get("KeyAlgorithm"),
                "not_after": not_after.isoformat() if not_after else "",
                "days_left": _days_left(not_after, now),
                "renewal_eligibility": "",
                "in_use_by": "",
                "owner": "",
            }


def at_risk(rows: list[dict], threshold_days: int, ca_threshold_days: int) -> list[dict]:
    risky = []
    for row in rows:
        if row["days_left"] is None or row["status"] in ("INACTIVE", "DELETED", "FAILED"):
            continue
        limit = ca_threshold_days if row["kind"] == "certificate-authority" else threshold_days
        if row["days_left"] < limit:
            risky.append(row)
    return risky


def render(rows: list[dict], fmt: str) -> str:
    if fmt == "json":
        return json.dumps(rows, indent=2, default=str)
    if fmt == "csv":
        out = io.StringIO()
        writer = csv.DictWriter(out, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
        return out.getvalue()
    lines = [f"{'KIND':<22} {'DAYS':>5}  {'STATUS':<18} NAME"]
    for r in sorted(rows, key=lambda r: (r["days_left"] is None, r["days_left"] or 0)):
        lines.append(f"{r['kind']:<22} {str(r['days_left']):>5}  {str(r['status']):<18} {r['name']}")
    return "\n".join(lines)


def collect(session, regions: list[str]) -> list[dict]:
    now = datetime.now(timezone.utc)
    rows: list[dict] = []
    for region in regions:
        rows.extend(acm_rows(session.client("acm", region_name=region), region, now))
        rows.extend(pca_rows(session.client("acm-pca", region_name=region), region, now))
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--regions", nargs="+", default=["ca-central-1", "us-east-1"])
    parser.add_argument("--threshold-days", type=int, default=30, help="alert threshold for certificates")
    parser.add_argument("--ca-threshold-days", type=int, default=540, help="alert threshold for CAs (18 months: time to plan a rotation)")
    parser.add_argument("--format", choices=["table", "csv", "json"], default="table")
    parser.add_argument("--output", help="write the report to this file instead of stdout")
    parser.add_argument("--summary-file", help="write a Markdown summary of at-risk items (used by CI)")
    args = parser.parse_args(argv)

    try:
        import boto3

        rows = collect(boto3.Session(), args.regions)
    except Exception as exc:  # noqa: BLE001
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    report = render(rows, args.format)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report)
    else:
        print(report)

    risky = at_risk(rows, args.threshold_days, args.ca_threshold_days)
    if args.summary_file:
        with open(args.summary_file, "w", encoding="utf-8") as fh:
            fh.write(f"## PKI inventory: {len(rows)} items, {len(risky)} at risk\n\n")
            if risky:
                fh.write("| Kind | Name | Days left | Status | Owner | ARN |\n|---|---|---|---|---|---|\n")
                for r in risky:
                    fh.write(f"| {r['kind']} | {r['name']} | {r['days_left']} | {r['status']} | {r['owner'] or 'UNKNOWN'} | `{r['arn']}` |\n")
    for r in risky:
        print(f"AT RISK: {r['kind']} {r['name']} expires in {r['days_left']} days ({r['arn']})", file=sys.stderr)
    return 2 if risky else 0


if __name__ == "__main__":
    sys.exit(main())
