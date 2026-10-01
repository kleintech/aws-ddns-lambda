"""dyndns2-style Route 53 updater behind a Lambda Function URL.

Updates a single A record. Called by inadyn (UniFi "custom" provider) as
GET /nic/update?hostname=<fqdn>&myip=<ipv4> with HTTP Basic auth.
"""

import base64
import binascii
import hmac
import ipaddress
import json
import logging
import os
from urllib.parse import parse_qs

import boto3
from botocore.config import Config

logger = logging.getLogger()
logger.setLevel(logging.INFO)

HOSTED_ZONE_ID = os.environ["HOSTED_ZONE_ID"]
RECORD_NAME = os.environ["RECORD_NAME"].lower().rstrip(".")
TTL = int(os.environ["TTL"])
CREDENTIAL_PARAM_NAME = os.environ["CREDENTIAL_PARAM_NAME"]

# Keep worst-case AWS calls well inside the 10s function timeout.
_BOTO_CONFIG = Config(connect_timeout=2, read_timeout=3, retries={"max_attempts": 2, "mode": "standard"})
ssm = boto3.client("ssm", config=_BOTO_CONFIG)
route53 = boto3.client("route53", config=_BOTO_CONFIG)

# "user:pass" as bytes, loaded once per execution environment (cold start).
_credentials = None


def _response(status, body, headers=None):
    return {
        "statusCode": status,
        "headers": {"Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store", **(headers or {})},
        "body": body,
    }


def _log(request_id, result, hostname=None, ip=None, ip_source=None):
    # Never log the Authorization header, the credentials, or the raw query string.
    logger.info(
        json.dumps(
            {
                "request_id": request_id,
                "hostname": hostname[:255] if hostname else hostname,
                "ip": ip,
                "ip_source": ip_source,
                "result": result,
            }
        )
    )


def _load_credentials():
    global _credentials
    if _credentials is None:
        value = ssm.get_parameter(Name=CREDENTIAL_PARAM_NAME, WithDecryption=True)["Parameter"]["Value"]
        value = value.rstrip("\r\n")
        user, sep, password = value.partition(":")
        if not sep or not user or not password:
            raise ValueError("credential parameter is not in user:pass form")
        _credentials = value.encode("utf-8")
    return _credentials


def _parse_basic_auth(headers):
    """Return the decoded "user:pass" bytes from a Basic Authorization header, or None."""
    header = headers.get("authorization")
    if not header:
        return None
    scheme, _, token = header.strip().partition(" ")
    if scheme.lower() != "basic" or not token:
        return None
    try:
        decoded = base64.b64decode(token.strip(), validate=True)
    except (binascii.Error, ValueError):
        return None
    if b":" not in decoded:
        return None
    return decoded


def _single(params, name):
    """Return the parameter's value only if it was supplied exactly once."""
    values = params.get(name)
    if not values or len(values) != 1:
        return None
    return values[0]


def _global_ipv4(value):
    if not value:
        return None
    try:
        addr = ipaddress.IPv4Address(value.strip())
    except ValueError:
        return None
    return str(addr) if addr.is_global else None


def _current_values(record_fqdn):
    """Return (values, ttl) of the existing simple A record, or (None, None)."""
    resp = route53.list_resource_record_sets(
        HostedZoneId=HOSTED_ZONE_ID,
        StartRecordName=record_fqdn,
        StartRecordType="A",
        MaxItems="1",
    )
    for rrset in resp.get("ResourceRecordSets", []):
        if rrset["Name"].lower() == record_fqdn and rrset["Type"] == "A" and "SetIdentifier" not in rrset:
            return [rr["Value"] for rr in rrset.get("ResourceRecords", [])], rrset.get("TTL")
    return None, None


def handler(event, context):
    request_id = getattr(context, "aws_request_id", None)
    try:
        return _handle(event, request_id)
    except Exception:
        # The traceback never contains the request headers or the stored credential.
        logger.exception("internal error request_id=%s", request_id)
        _log(request_id, "911")
        return _response(500, "911")


def _handle(event, request_id):
    http = event.get("requestContext", {}).get("http", {})
    if http.get("method") != "GET":
        _log(request_id, "badmethod")
        return _response(405, "badrequest", {"Allow": "GET"})
    if event.get("rawPath") != "/nic/update":
        _log(request_id, "notfound")
        return _response(404, "notfound")

    unauthorized = _response(401, "badauth", {"WWW-Authenticate": 'Basic realm="ddns", charset="UTF-8"'})
    headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
    supplied = _parse_basic_auth(headers)
    if supplied is None:
        _log(request_id, "badauth")
        return unauthorized
    if not hmac.compare_digest(supplied, _load_credentials()):
        _log(request_id, "badauth")
        return unauthorized

    params = parse_qs(event.get("rawQueryString") or "", keep_blank_values=True)
    hostname = _single(params, "hostname")
    if hostname is None or hostname.strip().lower().rstrip(".") != RECORD_NAME:
        _log(request_id, "nohost", hostname=hostname)
        return _response(200, "nohost")

    ip = _global_ipv4(_single(params, "myip"))
    ip_source = "myip"
    if ip is None:
        ip = _global_ipv4(http.get("sourceIp"))
        ip_source = "sourceIp"
    if ip is None:
        _log(request_id, "badip", hostname=RECORD_NAME)
        return _response(400, "badip")

    record_fqdn = RECORD_NAME + "."
    values, ttl = _current_values(record_fqdn)
    if values == [ip] and ttl == TTL:
        _log(request_id, "nochg", hostname=RECORD_NAME, ip=ip, ip_source=ip_source)
        return _response(200, f"nochg {ip}")

    route53.change_resource_record_sets(
        HostedZoneId=HOSTED_ZONE_ID,
        ChangeBatch={
            "Comment": "ddns update",
            "Changes": [
                {
                    "Action": "UPSERT",
                    "ResourceRecordSet": {
                        "Name": record_fqdn,
                        "Type": "A",
                        "TTL": TTL,
                        "ResourceRecords": [{"Value": ip}],
                    },
                }
            ],
        },
    )
    _log(request_id, "good", hostname=RECORD_NAME, ip=ip, ip_source=ip_source)
    return _response(200, f"good {ip}")
