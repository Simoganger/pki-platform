"""Unit tests for lambda/crl_freshness_checker (no AWS, no network beyond localhost)."""

from __future__ import annotations

import http.server
import threading
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

import handler_crl as crl

NOW = datetime(2026, 10, 5, 12, 0, 0, tzinfo=timezone.utc)


def make_crl(this_update: datetime, next_update: datetime, revoked: int = 0, pem: bool = False) -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Issuing CA")])
    builder = x509.CertificateRevocationListBuilder().issuer_name(issuer).last_update(this_update).next_update(next_update)
    for serial in range(1, revoked + 1):
        builder = builder.add_revoked_certificate(
            x509.RevokedCertificateBuilder().serial_number(serial).revocation_date(this_update).build()
        )
    crl_obj = builder.sign(key, hashes.SHA256())
    return crl_obj.public_bytes(serialization.Encoding.PEM if pem else serialization.Encoding.DER)


def test_parse_der_crl():
    this_update = NOW - timedelta(hours=2)
    next_update = NOW + timedelta(days=7)
    times = crl.parse_crl_times(make_crl(this_update, next_update))
    assert times.this_update == this_update
    assert times.next_update == next_update


def test_parse_pem_crl_with_many_entries():
    this_update = NOW - timedelta(hours=1)
    next_update = NOW + timedelta(days=1)
    times = crl.parse_crl_times(make_crl(this_update, next_update, revoked=500, pem=True))
    assert times.next_update == next_update


def test_parse_generalized_time_after_2049():
    this_update = datetime(2050, 1, 1, tzinfo=timezone.utc)
    next_update = datetime(2050, 1, 8, tzinfo=timezone.utc)
    times = crl.parse_crl_times(make_crl(this_update, next_update))
    assert times.this_update.year == 2050
    assert times.next_update == next_update


def test_garbage_is_rejected():
    with pytest.raises(crl.CrlParseError):
        crl.parse_crl_times(b"<html>Not Found</html>")


@pytest.fixture()
def crl_server():
    payloads: dict[str, bytes] = {}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            body = payloads.get(self.path)
            if body is None:
                self.send_response(404)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/pkix-crl")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}", payloads
    server.shutdown()


def test_check_fresh_and_expired(crl_server):
    base, payloads = crl_server
    payloads["/crl/fresh.crl"] = make_crl(NOW - timedelta(hours=1), NOW + timedelta(days=7))
    payloads["/crl/expired.crl"] = make_crl(NOW - timedelta(days=8), NOW - timedelta(hours=3))

    fresh = crl.check(f"{base}/crl/fresh.crl", NOW)
    expired = crl.check(f"{base}/crl/expired.crl", NOW)
    missing = crl.check(f"{base}/crl/missing.crl", NOW)

    assert fresh["status"] == "OK" and fresh["fetch_success"] == 1
    assert fresh["hours_until_next_update"] == pytest.approx(168, abs=0.1)
    assert expired["status"] == "EXPIRED" and expired["hours_until_next_update"] < 0
    assert missing["status"] == "ERROR" and missing["fetch_success"] == 0


def test_handler_publishes_metrics(crl_server, monkeypatch):
    base, payloads = crl_server
    payloads["/a.crl"] = make_crl(datetime.now(timezone.utc) - timedelta(hours=1), datetime.now(timezone.utc) + timedelta(days=2))
    monkeypatch.setenv("CRL_URLS", f"{base}/a.crl,{base}/missing.crl")

    class FakeCloudWatch:
        def __init__(self):
            self.calls = []

        def put_metric_data(self, Namespace, MetricData):  # noqa: N803
            self.calls.append((Namespace, MetricData))

    cw = FakeCloudWatch()
    result = crl.lambda_handler({}, None, cloudwatch=cw)

    assert result["checked"] == 2
    assert result["unhealthy"] == [f"{base}/missing.crl"]
    names = {m["MetricName"] for _, batch in cw.calls for m in batch}
    assert {"FetchSuccess", "HoursUntilNextUpdate", "HoursSinceThisUpdate", "SizeBytes"} <= names
    assert all(ns == "PKI/CRL" for ns, _ in cw.calls)


def test_rejects_non_http_scheme():
    result = crl.check("file:///etc/passwd", NOW)
    assert result["status"] == "ERROR"
