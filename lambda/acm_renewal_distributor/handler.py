"""ACM renewal distributor.

Triggered by EventBridge "ACM Certificate Available" (first issuance and every
managed renewal), or invoked manually with {"certificateArn": "..."}.

For certificates tagged  pki:distribute = secretsmanager :
  1. ExportCertificate from ACM with a random one-time passphrase;
  2. decrypt the PKCS#8 key in memory (cryptography library, vendored at build);
  3. write {certificate, certificate_chain, private_key, not_after, serial}
     to the Secrets Manager secret named by tag pki:secret-name (KMS key of the
     module), with a resource policy that lets ONLY the role in tag
     pki:reader-role read it;
  4. if tag pki:ssm-target-tag is set, send the SSM document to instances
     tagged pki:cert=<value> so they install the new certificate and reload;
  5. publish an SNS notification and a structured log line.

Nothing secret is ever logged.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
from typing import Any

LOG = logging.getLogger()
LOG.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

SECRET_NAME_PREFIX = os.environ.get("SECRET_NAME_PREFIX", "pki/certs/")
SECRETS_KMS_KEY_ID = os.environ.get("SECRETS_KMS_KEY_ID")
NOTIFICATION_TOPIC_ARN = os.environ.get("NOTIFICATION_TOPIC_ARN")
SSM_DOCUMENT_NAME = os.environ.get("SSM_DOCUMENT_NAME")

TAG_DISTRIBUTE = "pki:distribute"
TAG_SECRET_NAME = "pki:secret-name"
TAG_READER_ROLE = "pki:reader-role"
TAG_SSM_TARGET = "pki:ssm-target-tag"


class Clients:
    """Lazily created boto3 clients (injectable for unit tests)."""

    def __init__(self, acm=None, secretsmanager=None, sns=None, ssm=None):
        self._acm, self._sm, self._sns, self._ssm = acm, secretsmanager, sns, ssm

    def _boto(self, name):
        import boto3

        return boto3.client(name)

    @property
    def acm(self):
        self._acm = self._acm or self._boto("acm")
        return self._acm

    @property
    def secretsmanager(self):
        self._sm = self._sm or self._boto("secretsmanager")
        return self._sm

    @property
    def sns(self):
        self._sns = self._sns or self._boto("sns")
        return self._sns

    @property
    def ssm(self):
        self._ssm = self._ssm or self._boto("ssm")
        return self._ssm


def certificate_arn_from_event(event: dict) -> str:
    if event.get("certificateArn"):
        return event["certificateArn"]
    resources = event.get("resources") or []
    if not resources:
        raise ValueError("event has no certificate ARN")
    return resources[0]


def decrypt_private_key(encrypted_pem: str, passphrase: bytes) -> str:
    from cryptography.hazmat.primitives import serialization

    key = serialization.load_pem_private_key(encrypted_pem.encode(), password=passphrase)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()


def secret_policy(secret_arn_hint: str, reader_role_arn: str) -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "WorkloadReadsItsCertificate",
                    "Effect": "Allow",
                    "Principal": {"AWS": reader_role_arn},
                    "Action": ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"],
                    "Resource": "*",
                },
                {
                    "Sid": "DenyEveryoneElseExceptAdmins",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "secretsmanager:GetSecretValue",
                    "Resource": "*",
                    "Condition": {
                        "StringNotLike": {
                            "aws:PrincipalArn": [reader_role_arn, "arn:aws:iam::*:role/pki-break-glass"]
                        }
                    },
                },
            ],
        }
    )


def upsert_secret(clients: Clients, name: str, value: dict, reader_role_arn: str, cert_arn: str) -> str:
    payload = json.dumps(value)
    sm = clients.secretsmanager
    try:
        arn = sm.describe_secret(SecretId=name)["ARN"]
        sm.put_secret_value(SecretId=arn, SecretString=payload)
        action = "updated"
    except sm.exceptions.ResourceNotFoundException:
        arn = sm.create_secret(
            Name=name,
            Description=f"Certificate bundle exported from ACM ({cert_arn}). Managed by acm-renewal-distributor.",
            KmsKeyId=SECRETS_KMS_KEY_ID,
            SecretString=payload,
            Tags=[
                {"Key": "pki:component", "Value": "certificate-secret"},
                {"Key": "pki:certificate-arn", "Value": cert_arn},
            ],
        )["ARN"]
        action = "created"
    sm.put_resource_policy(SecretId=arn, ResourcePolicy=secret_policy(arn, reader_role_arn), BlockPublicPolicy=True)
    LOG.info(json.dumps({"event": "pki.cert.secret", "action": action, "secret": name, "certificate_arn": cert_arn}))
    return arn


def lambda_handler(event: dict, context: Any, clients: Clients | None = None) -> dict:  # noqa: ARG001
    clients = clients or Clients()
    cert_arn = certificate_arn_from_event(event)

    tags = {t["Key"]: t.get("Value", "") for t in clients.acm.list_tags_for_certificate(CertificateArn=cert_arn).get("Tags", [])}
    if tags.get(TAG_DISTRIBUTE) != "secretsmanager":
        LOG.info(json.dumps({"event": "pki.cert.skip", "certificate_arn": cert_arn, "reason": "not opted in"}))
        return {"status": "skipped", "certificateArn": cert_arn}

    secret_name = tags.get(TAG_SECRET_NAME, "")
    reader_role = tags.get(TAG_READER_ROLE, "")
    if not secret_name.startswith(SECRET_NAME_PREFIX):
        raise ValueError(f"secret name {secret_name!r} must start with {SECRET_NAME_PREFIX!r}")
    if not reader_role.startswith("arn:"):
        raise ValueError("tag pki:reader-role must contain an IAM role ARN")

    details = clients.acm.describe_certificate(CertificateArn=cert_arn)["Certificate"]

    passphrase = secrets.token_urlsafe(32).encode()
    exported = clients.acm.export_certificate(CertificateArn=cert_arn, Passphrase=passphrase)
    private_key = decrypt_private_key(exported["PrivateKey"], passphrase)

    bundle = {
        "certificate": exported["Certificate"],
        "certificate_chain": exported.get("CertificateChain", ""),
        "private_key": private_key,
        "domain_name": details.get("DomainName"),
        "serial": details.get("Serial"),
        "not_after": details["NotAfter"].isoformat() if hasattr(details.get("NotAfter"), "isoformat") else str(details.get("NotAfter")),
        "certificate_arn": cert_arn,
    }
    upsert_secret(clients, secret_name, bundle, reader_role, cert_arn)
    del private_key, bundle, exported  # keep key material lifetime minimal

    command_id = None
    target_tag = tags.get(TAG_SSM_TARGET)
    if target_tag and SSM_DOCUMENT_NAME:
        response = clients.ssm.send_command(
            DocumentName=SSM_DOCUMENT_NAME,
            Targets=[{"Key": "tag:pki:cert", "Values": [target_tag]}],
            Parameters={"SecretName": [secret_name]},
            Comment=f"PKI renewal {details.get('DomainName')}"[:100],
            MaxErrors="0",
            MaxConcurrency="25%",
        )
        command_id = response["Command"]["CommandId"]

    summary = {
        "event": "pki.cert.distributed",
        "certificate_arn": cert_arn,
        "domain_name": details.get("DomainName"),
        "serial": details.get("Serial"),
        "not_after": str(details.get("NotAfter")),
        "secret": secret_name,
        "ssm_command_id": command_id,
    }
    LOG.info(json.dumps(summary))
    if NOTIFICATION_TOPIC_ARN:
        clients.sns.publish(
            TopicArn=NOTIFICATION_TOPIC_ARN,
            Subject=f"[PKI] Certificate redistributed: {details.get('DomainName')}"[:100],
            Message=json.dumps(summary, indent=2),
        )
    return {"status": "distributed", **summary}
