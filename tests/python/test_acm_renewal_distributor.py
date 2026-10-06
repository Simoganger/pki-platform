"""Unit tests for lambda/acm_renewal_distributor with fake AWS clients."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

import handler_distributor as dist

CERT_ARN = "arn:aws:acm:ca-central-1:444444444444:certificate/11111111-2222-3333-4444-555555555555"
READER = "arn:aws:iam::444444444444:role/pki-payments-batch-instance"


class NotFound(Exception):
    pass


class FakeACM:
    def __init__(self, tags):
        self.tags = tags
        self.exported_with = None

    def list_tags_for_certificate(self, CertificateArn):  # noqa: N803
        return {"Tags": [{"Key": k, "Value": v} for k, v in self.tags.items()]}

    def describe_certificate(self, CertificateArn):  # noqa: N803
        return {"Certificate": {"DomainName": "payments-batch.nonprod.internal.example.com", "Serial": "0a:0b", "NotAfter": datetime(2027, 11, 5, tzinfo=timezone.utc)}}

    def export_certificate(self, CertificateArn, Passphrase):  # noqa: N803
        self.exported_with = Passphrase
        key = ec.generate_private_key(ec.SECP256R1())
        encrypted = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(Passphrase),
        ).decode()
        return {"Certificate": "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n", "CertificateChain": "CHAIN", "PrivateKey": encrypted}


class FakeSecretsManager:
    class exceptions:  # noqa: N801 - mimics boto3 client.exceptions
        ResourceNotFoundException = NotFound

    def __init__(self, existing=False):
        self.existing = existing
        self.created = None
        self.updated = None
        self.policy = None

    def describe_secret(self, SecretId):  # noqa: N803
        if not self.existing:
            raise NotFound()
        return {"ARN": f"arn:aws:secretsmanager:ca-central-1:444444444444:secret:{SecretId}-AbCdEf"}

    def create_secret(self, **kwargs):
        self.created = kwargs
        return {"ARN": f"arn:aws:secretsmanager:ca-central-1:444444444444:secret:{kwargs['Name']}-AbCdEf"}

    def put_secret_value(self, SecretId, SecretString):  # noqa: N803
        self.updated = (SecretId, SecretString)

    def put_resource_policy(self, SecretId, ResourcePolicy, BlockPublicPolicy):  # noqa: N803
        self.policy = json.loads(ResourcePolicy)


class FakeSNS:
    def __init__(self):
        self.messages = []

    def publish(self, **kwargs):
        self.messages.append(kwargs)


class FakeSSM:
    def __init__(self):
        self.commands = []

    def send_command(self, **kwargs):
        self.commands.append(kwargs)
        return {"Command": {"CommandId": "cmd-123"}}


@pytest.fixture(autouse=True)
def env(monkeypatch):
    monkeypatch.setattr(dist, "NOTIFICATION_TOPIC_ARN", "arn:aws:sns:ca-central-1:444444444444:pki-alerts")
    monkeypatch.setattr(dist, "SSM_DOCUMENT_NAME", "pki-payments-nonprod-ReloadCertificate")


def opted_in_tags(**extra):
    tags = {
        "pki:distribute": "secretsmanager",
        "pki:secret-name": "pki/certs/payments-batch.nonprod.internal.example.com",
        "pki:reader-role": READER,
        "pki:ssm-target-tag": "payments-batch",
    }
    tags.update(extra)
    return tags


def test_skips_certificates_not_opted_in():
    clients = dist.Clients(acm=FakeACM({"pki:owner": "x"}))
    assert dist.lambda_handler({"resources": [CERT_ARN]}, None, clients)["status"] == "skipped"


def test_first_distribution_creates_secret_with_decrypted_key():
    acm, sm, sns, ssm = FakeACM(opted_in_tags()), FakeSecretsManager(), FakeSNS(), FakeSSM()
    result = dist.lambda_handler({"detail-type": "ACM Certificate Available", "resources": [CERT_ARN]}, None, dist.Clients(acm, sm, sns, ssm))

    assert result["status"] == "distributed"
    bundle = json.loads(sm.created["SecretString"])
    assert bundle["private_key"].startswith("-----BEGIN PRIVATE KEY-----")  # decrypted PKCS#8
    assert "ENCRYPTED" not in bundle["private_key"]
    assert len(acm.exported_with) >= 32  # random one-time passphrase
    assert sm.policy["Statement"][0]["Principal"]["AWS"] == READER
    assert ssm.commands[0]["Targets"] == [{"Key": "tag:pki:cert", "Values": ["payments-batch"]}]
    assert ssm.commands[0]["Parameters"] == {"SecretName": ["pki/certs/payments-batch.nonprod.internal.example.com"]}
    assert "PRIVATE KEY" not in sns.messages[0]["Message"]  # never leak the key in notifications


def test_renewal_updates_existing_secret():
    sm = FakeSecretsManager(existing=True)
    dist.lambda_handler({"certificateArn": CERT_ARN}, None, dist.Clients(FakeACM(opted_in_tags()), sm, FakeSNS(), FakeSSM()))
    assert sm.updated is not None and sm.created is None


def test_rejects_secret_outside_prefix():
    tags = opted_in_tags(**{"pki:secret-name": "prod/db-password"})
    with pytest.raises(ValueError, match="must start with"):
        dist.lambda_handler({"certificateArn": CERT_ARN}, None, dist.Clients(FakeACM(tags), FakeSecretsManager(), FakeSNS(), FakeSSM()))


def test_no_ssm_when_no_target_tag():
    ssm = FakeSSM()
    tags = opted_in_tags(**{"pki:ssm-target-tag": ""})
    dist.lambda_handler({"certificateArn": CERT_ARN}, None, dist.Clients(FakeACM(tags), FakeSecretsManager(), FakeSNS(), ssm))
    assert ssm.commands == []
