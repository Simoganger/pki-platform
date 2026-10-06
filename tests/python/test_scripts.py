"""Unit tests for scripts/ (name constraints builder and inventory logic)."""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

import build_name_constraints as bnc
import cert_inventory as inv


def test_name_constraints_roundtrip_and_enforced_by_validator():
    nc = bnc.build([".internal.example.com"], [".corp.example.com"])
    der = base64.b64decode(bnc.to_base64(nc))

    # Embed it in a CA certificate and parse it back: proves the DER is valid.
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Constrained CA")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.UnrecognizedExtension(x509.ObjectIdentifier("2.5.29.30"), der), critical=True)
        .sign(key, hashes.SHA256())
    )
    parsed = cert.extensions.get_extension_for_class(x509.NameConstraints).value
    assert [n.value for n in parsed.permitted_subtrees] == [".internal.example.com"]
    assert [n.value for n in parsed.excluded_subtrees] == [".corp.example.com"]


@pytest.mark.parametrize("bad", ["*.example.com", "https://example.com", "exa mple.com"])
def test_name_constraints_reject_bad_input(bad):
    with pytest.raises(ValueError):
        bnc.build([bad], [])


def test_openssl_snippet():
    snippet = bnc.to_openssl([".pci.internal.example.com"], [])
    assert "nameConstraints = critical, @name_constraints" in snippet
    assert "permitted;DNS.0 = pci.internal.example.com" in snippet


NOW = datetime(2026, 10, 5, tzinfo=timezone.utc)


class FakePaginator:
    def __init__(self, pages):
        self.pages = pages

    def paginate(self, **_):
        return iter(self.pages)


class FakeACM:
    def get_paginator(self, _):
        return FakePaginator([{"CertificateSummaryList": [{"CertificateArn": "arn:cert/1"}, {"CertificateArn": "arn:cert/2"}]}])

    def describe_certificate(self, CertificateArn):  # noqa: N803
        days = 10 if CertificateArn.endswith("1") else 200
        return {"Certificate": {
            "DomainName": f"svc{CertificateArn[-1]}.internal.example.com",
            "Type": "PRIVATE",
            "Status": "ISSUED",
            "CertificateAuthorityArn": "arn:ca/1",
            "KeyAlgorithm": "EC_prime256v1",
            "NotAfter": NOW + timedelta(days=days),
            "RenewalEligibility": "ELIGIBLE",
            "InUseBy": ["arn:aws:elasticloadbalancing:...:loadbalancer/app/x"],
        }}

    def list_tags_for_certificate(self, CertificateArn):  # noqa: N803
        return {"Tags": [{"Key": "pki:owner", "Value": "team-a@example.com"}]}


class FakePCA:
    def get_paginator(self, _):
        return FakePaginator([{"CertificateAuthorities": [{
            "Arn": "arn:ca/1", "Type": "SUBORDINATE", "Status": "ACTIVE", "UsageMode": "GENERAL_PURPOSE",
            "NotAfter": NOW + timedelta(days=400),
            "CertificateAuthorityConfiguration": {"KeyAlgorithm": "EC_prime256v1", "Subject": {"CommonName": "Servers Issuing CA G1"}},
        }]}])


def test_inventory_flags_items_under_threshold():
    rows = list(inv.acm_rows(FakeACM(), "ca-central-1", NOW)) + list(inv.pca_rows(FakePCA(), "ca-central-1", NOW))
    assert len(rows) == 3
    risky = inv.at_risk(rows, threshold_days=30, ca_threshold_days=540)
    names = sorted(r["name"] for r in risky)
    # svc1 expires in 10 days; the CA has 400 days left (< 18 months: plan the rotation)
    assert names == ["Servers Issuing CA G1", "svc1.internal.example.com"]
    csv_text = inv.render(rows, "csv")
    assert csv_text.splitlines()[0].startswith("kind,region,name,arn")
