#!/usr/bin/env python3
"""Generate and download an AWS Private CA audit report.

An audit report lists every certificate a CA issued or revoked (serial,
subject, validity, revocation reason). It is the authoritative evidence for
auditors (PCI DSS 4.2.1.1 / 10.x) and the starting point after a suspected CA
compromise ("what did this CA sign?").

  python scripts/pca_audit_report.py \
      --ca-arn arn:aws:acm-pca:ca-central-1:111111111111:certificate-authority/xxxx \
      --bucket pki-nonprod-crl-111111111111 --format CSV --output audit.csv

Notes
  - The bucket must allow acm-pca.amazonaws.com to write (the CRL bucket does).
  - AWS limits audit report creation (one report per CA every 30 minutes).
"""

from __future__ import annotations

import argparse
import sys
import time


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--ca-arn", required=True)
    parser.add_argument("--bucket", required=True)
    parser.add_argument("--format", choices=["CSV", "JSON"], default="CSV")
    parser.add_argument("--output", required=True)
    parser.add_argument("--region", default=None)
    parser.add_argument("--timeout", type=int, default=600)
    args = parser.parse_args(argv)

    import boto3

    region = args.region or args.ca_arn.split(":")[3]
    pca = boto3.client("acm-pca", region_name=region)
    s3 = boto3.client("s3", region_name=region)

    created = pca.create_certificate_authority_audit_report(
        CertificateAuthorityArn=args.ca_arn,
        S3BucketName=args.bucket,
        AuditReportResponseFormat=args.format,
    )
    report_id, key = created["AuditReportId"], created["S3Key"]
    print(f"Audit report {report_id} requested -> s3://{args.bucket}/{key}", file=sys.stderr)

    deadline = time.time() + args.timeout
    while time.time() < deadline:
        status = pca.describe_certificate_authority_audit_report(
            CertificateAuthorityArn=args.ca_arn, AuditReportId=report_id
        )["AuditReportStatus"]
        if status == "SUCCESS":
            s3.download_file(args.bucket, key, args.output)
            print(f"Downloaded to {args.output}", file=sys.stderr)
            return 0
        if status == "FAILED":
            print("Audit report FAILED (check bucket policy and CloudTrail).", file=sys.stderr)
            return 1
        time.sleep(10)

    print("Timed out waiting for the audit report.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
