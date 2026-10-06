"""CRL freshness checker.

Runs every 15 minutes (EventBridge schedule). For each CRL URL it:
  1. downloads the CRL (DER or PEM) exactly like a relying party would;
  2. parses thisUpdate / nextUpdate with a tiny standard-library DER reader
     (no third-party dependency, so no build step and no supply-chain surface);
  3. publishes CloudWatch metrics in namespace PKI/CRL, dimension CrlUrl:
       FetchSuccess          1 = downloaded and parsed, 0 = failure
       HoursUntilNextUpdate  < 0 means the CRL is EXPIRED
       HoursSinceThisUpdate  age of the CRL
       SizeBytes             growth of a CRL is a capacity signal
  4. writes one structured JSON log line per CRL (picked up by Splunk/Datadog).

Why this matters: when a CRL passes its nextUpdate, hard-fail clients reject
every certificate issued by that CA - the whole CA is effectively down.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone

LOG = logging.getLogger()
LOG.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

NAMESPACE = os.environ.get("METRIC_NAMESPACE", "PKI/CRL")
TIMEOUT_SECONDS = float(os.environ.get("FETCH_TIMEOUT_SECONDS", "10"))
MAX_CRL_BYTES = int(os.environ.get("MAX_CRL_BYTES", str(50 * 1024 * 1024)))

TAG_INTEGER = 0x02
TAG_SEQUENCE = 0x30
TAG_UTCTIME = 0x17
TAG_GENERALIZEDTIME = 0x18


class CrlParseError(ValueError):
    """Raised when the payload is not a well-formed X.509 CRL."""


@dataclass(frozen=True)
class CrlTimes:
    this_update: datetime
    next_update: datetime | None


def _read_tlv(data: bytes, pos: int) -> tuple[int, int, int]:
    """Read one DER TLV header. Returns (tag, value_start, value_length)."""
    if pos + 2 > len(data):
        raise CrlParseError("truncated DER header")
    tag = data[pos]
    length = data[pos + 1]
    pos += 2
    if length & 0x80:
        num_bytes = length & 0x7F
        if num_bytes == 0 or num_bytes > 4 or pos + num_bytes > len(data):
            raise CrlParseError("unsupported DER length encoding")
        length = int.from_bytes(data[pos : pos + num_bytes], "big")
        pos += num_bytes
    if pos + length > len(data):
        raise CrlParseError("DER value runs past end of data")
    return tag, pos, length


def _parse_time(tag: int, raw: bytes) -> datetime:
    text = raw.decode("ascii")
    if not text.endswith("Z"):
        raise CrlParseError(f"time without Z suffix: {text!r}")
    if tag == TAG_UTCTIME:  # YYMMDDHHMMSSZ, RFC 5280: YY >= 50 -> 19YY
        year = int(text[0:2])
        year += 1900 if year >= 50 else 2000
        rest = text[2:-1]
    elif tag == TAG_GENERALIZEDTIME:  # YYYYMMDDHHMMSSZ
        year = int(text[0:4])
        rest = text[4:-1]
    else:
        raise CrlParseError(f"unexpected time tag 0x{tag:02x}")
    return datetime(
        year,
        int(rest[0:2]),
        int(rest[2:4]),
        int(rest[4:6]),
        int(rest[6:8]),
        int(rest[8:10]),
        tzinfo=timezone.utc,
    )


def to_der(payload: bytes) -> bytes:
    """Accept DER or PEM ('-----BEGIN X509 CRL-----')."""
    stripped = payload.strip()
    if stripped.startswith(b"-----BEGIN"):
        lines = [ln for ln in stripped.splitlines() if not ln.startswith(b"-----")]
        return base64.b64decode(b"".join(lines))
    return payload


def parse_crl_times(payload: bytes) -> CrlTimes:
    """Extract thisUpdate and nextUpdate from a CRL (RFC 5280 section 5.1).

    CertificateList  ::= SEQUENCE { tbsCertList, signatureAlgorithm, signatureValue }
    TBSCertList      ::= SEQUENCE {
        version     Version OPTIONAL,     -- INTEGER
        signature   AlgorithmIdentifier,  -- SEQUENCE
        issuer      Name,                 -- SEQUENCE
        thisUpdate  Time,
        nextUpdate  Time OPTIONAL, ... }
    """
    der = to_der(payload)
    tag, pos, _ = _read_tlv(der, 0)
    if tag != TAG_SEQUENCE:
        raise CrlParseError("CertificateList is not a SEQUENCE")
    tag, pos, tbs_len = _read_tlv(der, pos)
    if tag != TAG_SEQUENCE:
        raise CrlParseError("tbsCertList is not a SEQUENCE")
    end = pos + tbs_len

    tag, vstart, vlen = _read_tlv(der, pos)
    if tag == TAG_INTEGER:  # optional version
        pos = vstart + vlen
        tag, vstart, vlen = _read_tlv(der, pos)

    for expected in ("signature", "issuer"):
        if tag != TAG_SEQUENCE:
            raise CrlParseError(f"{expected} is not a SEQUENCE")
        pos = vstart + vlen
        tag, vstart, vlen = _read_tlv(der, pos)

    this_update = _parse_time(tag, der[vstart : vstart + vlen])
    pos = vstart + vlen

    next_update = None
    if pos < end:
        tag, vstart, vlen = _read_tlv(der, pos)
        if tag in (TAG_UTCTIME, TAG_GENERALIZEDTIME):
            next_update = _parse_time(tag, der[vstart : vstart + vlen])

    return CrlTimes(this_update=this_update, next_update=next_update)


def fetch(url: str) -> bytes:
    if not url.startswith(("http://", "https://")):
        raise ValueError(f"unsupported URL scheme: {url}")
    request = urllib.request.Request(url, headers={"User-Agent": "pki-crl-freshness-checker/1.0"})
    with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:  # noqa: S310 (scheme checked)
        body = response.read(MAX_CRL_BYTES + 1)
    if len(body) > MAX_CRL_BYTES:
        raise ValueError("CRL larger than MAX_CRL_BYTES")
    return body


def check(url: str, now: datetime) -> dict:
    """Check one CRL and return the result record (never raises)."""
    result: dict = {"crl_url": url, "checked_at": now.isoformat(), "fetch_success": 0}
    try:
        body = fetch(url)
        times = parse_crl_times(body)
        result.update(
            fetch_success=1,
            size_bytes=len(body),
            this_update=times.this_update.isoformat(),
            next_update=times.next_update.isoformat() if times.next_update else None,
            hours_since_this_update=round((now - times.this_update).total_seconds() / 3600, 2),
        )
        if times.next_update:
            hours_left = (times.next_update - now).total_seconds() / 3600
            result["hours_until_next_update"] = round(hours_left, 2)
            result["status"] = "EXPIRED" if hours_left < 0 else "OK"
        else:
            result["status"] = "NO_NEXT_UPDATE"
    except Exception as exc:  # noqa: BLE001 - every failure must become a metric
        result["status"] = "ERROR"
        result["error"] = f"{type(exc).__name__}: {exc}"
    return result


def metric_data(result: dict) -> list[dict]:
    dims = [{"Name": "CrlUrl", "Value": result["crl_url"]}]
    data = [{"MetricName": "FetchSuccess", "Dimensions": dims, "Value": result["fetch_success"], "Unit": "Count"}]
    if "hours_until_next_update" in result:
        data.append({"MetricName": "HoursUntilNextUpdate", "Dimensions": dims, "Value": result["hours_until_next_update"], "Unit": "None"})
    if "hours_since_this_update" in result:
        data.append({"MetricName": "HoursSinceThisUpdate", "Dimensions": dims, "Value": result["hours_since_this_update"], "Unit": "None"})
    if "size_bytes" in result:
        data.append({"MetricName": "SizeBytes", "Dimensions": dims, "Value": result["size_bytes"], "Unit": "Bytes"})
    return data


def lambda_handler(event, context, cloudwatch=None):  # noqa: ARG001
    urls = [u.strip() for u in os.environ.get("CRL_URLS", "").split(",") if u.strip()]
    if not urls:
        LOG.warning(json.dumps({"message": "no CRL_URLS configured"}))
        return {"checked": 0}

    if cloudwatch is None:
        import boto3  # available in the Lambda runtime

        cloudwatch = boto3.client("cloudwatch")

    now = datetime.now(timezone.utc)
    results = [check(url, now) for url in urls]

    metrics: list[dict] = []
    for result in results:
        level = logging.INFO if result["status"] == "OK" else logging.ERROR
        LOG.log(level, json.dumps({"event": "pki.crl.check", **result}))
        metrics.extend(metric_data(result))

    for i in range(0, len(metrics), 20):  # PutMetricData: keep batches small
        cloudwatch.put_metric_data(Namespace=NAMESPACE, MetricData=metrics[i : i + 20])

    unhealthy = [r["crl_url"] for r in results if r["status"] != "OK"]
    return {"checked": len(results), "unhealthy": unhealthy}
