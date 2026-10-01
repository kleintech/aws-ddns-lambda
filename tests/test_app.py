import base64
import json
from types import SimpleNamespace

import pytest
from botocore.stub import Stubber

import app

ZONE = "Z0123456789ABCDEFGHIJ"
FQDN = "home.example.com."
CREDS = "udm:s3cret-pass"
CONTEXT = SimpleNamespace(aws_request_id="req-1")


def basic(userpass):
    return "Basic " + base64.b64encode(userpass.encode()).decode()


def event(query="hostname=home.example.com&myip=93.184.216.34", auth=basic(CREDS), source_ip="52.94.10.20",
          method="GET", path="/nic/update"):
    headers = {"user-agent": "inadyn/2.12.0"}
    if auth is not None:
        headers["authorization"] = auth
    return {
        "version": "2.0",
        "rawPath": path,
        "rawQueryString": query,
        "headers": headers,
        "requestContext": {"http": {"method": method, "path": path, "sourceIp": source_ip}},
    }


@pytest.fixture
def aws():
    """Stub both clients; any AWS call not explicitly queued fails the request with 911."""
    app._credentials = None
    with Stubber(app.ssm) as ssm, Stubber(app.route53) as r53:
        yield SimpleNamespace(ssm=ssm, r53=r53)
        ssm.assert_no_pending_responses()
        r53.assert_no_pending_responses()
    app._credentials = None


def expect_ssm(aws, value=CREDS):
    aws.ssm.add_response(
        "get_parameter",
        {"Parameter": {"Name": "/ddns/credentials", "Type": "SecureString", "Value": value}},
        {"Name": "/ddns/credentials", "WithDecryption": True},
    )


def expect_read(aws, values, ttl=60, name=FQDN):
    rrsets = []
    if values is not None:
        rrsets.append({"Name": name, "Type": "A", "TTL": ttl, "ResourceRecords": [{"Value": v} for v in values]})
    aws.r53.add_response(
        "list_resource_record_sets",
        {"ResourceRecordSets": rrsets, "IsTruncated": False, "MaxItems": "1"},
        {"HostedZoneId": ZONE, "StartRecordName": FQDN, "StartRecordType": "A", "MaxItems": "1"},
    )


def expect_read_raw(aws, rrset):
    aws.r53.add_response(
        "list_resource_record_sets",
        {"ResourceRecordSets": [rrset], "IsTruncated": False, "MaxItems": "1"},
        {"HostedZoneId": ZONE, "StartRecordName": FQDN, "StartRecordType": "A", "MaxItems": "1"},
    )


def assert_911_from(resp, caplog, exc_name):
    """A 911 alone is ambiguous: an unexpected (unstubbed) AWS call also yields 911."""
    assert (resp["statusCode"], resp["body"]) == (500, "911")
    assert [r.exc_info[0].__name__ for r in caplog.records if r.exc_info] == [exc_name]


def log_lines(capsys):
    """The handler's per-request log lines, each of which must be bare JSON."""
    return [json.loads(line) for line in capsys.readouterr().out.splitlines()]


def expect_upsert(aws, ip):
    aws.r53.add_response(
        "change_resource_record_sets",
        {"ChangeInfo": {"Id": "/change/C1", "Status": "PENDING", "SubmittedAt": "2026-10-01T00:00:00Z"}},
        {
            "HostedZoneId": ZONE,
            "ChangeBatch": {
                "Comment": "ddns update",
                "Changes": [
                    {
                        "Action": "UPSERT",
                        "ResourceRecordSet": {
                            "Name": FQDN,
                            "Type": "A",
                            "TTL": 60,
                            "ResourceRecords": [{"Value": ip}],
                        },
                    }
                ],
            },
        },
    )


def call(ev):
    return app.handler(ev, CONTEXT)


# --- auth -------------------------------------------------------------------

def test_missing_auth_is_401_with_challenge_and_skips_aws(aws):
    # Bug caught: a request with no Authorization header reaching Route 53, or a 401 without
    # WWW-Authenticate (clients that wait for a challenge would never send credentials).
    resp = call(event(auth=None))
    assert resp["statusCode"] == 401
    assert resp["body"] == "badauth"
    assert resp["headers"]["WWW-Authenticate"].startswith("Basic ")


def test_wrong_password_is_401_and_never_reads_or_writes_dns(aws):
    # Bug caught: comparing only the username, or a prefix, letting a wrong password through.
    expect_ssm(aws)
    resp = call(event(auth=basic("udm:s3cret-pas")))
    assert resp["statusCode"] == 401
    assert resp["body"] == "badauth"


@pytest.mark.parametrize("auth", ["Bearer abc", "Basic", "Basic !!!notbase64", basic("nocolon")])
def test_malformed_auth_is_401(aws, auth):
    # Bug caught: a malformed header raising (500/911) instead of a clean badauth.
    resp = call(event(auth=auth))
    assert (resp["statusCode"], resp["body"]) == (401, "badauth")


def test_credentials_read_once_per_cold_start(aws):
    # Bug caught: hitting SSM on every request (latency, cost, throttling). Only one SSM
    # response is queued, so a second read would fail the second request with 911.
    expect_ssm(aws)
    expect_read(aws, ["93.184.216.34"])
    expect_read(aws, ["93.184.216.34"])
    assert call(event())["body"] == "nochg 93.184.216.34"
    assert call(event())["body"] == "nochg 93.184.216.34"


def test_ssm_failure_returns_911(aws):
    # Bug caught: an SSM error escaping as an unhandled crash, or being treated as auth success.
    aws.ssm.add_client_error("get_parameter", service_error_code="AccessDeniedException", http_status_code=400)
    resp = call(event())
    assert (resp["statusCode"], resp["body"]) == (500, "911")
    assert app._credentials is None  # a transient failure must not poison the cache


def test_malformed_stored_credential_returns_911(aws, caplog):
    # Bug caught: a parameter without "user:" (e.g. password only) silently accepting any username.
    expect_ssm(aws, value="justapassword")
    assert_911_from(call(event(auth=basic("x:justapassword"))), caplog, "ValueError")


@pytest.mark.parametrize("stored", [":onlypass", "onlyuser:"])
def test_stored_credential_with_empty_half_returns_911(aws, stored, caplog):
    # Bug caught: an empty username or password in SSM making "user:" or ":pass" a valid login.
    expect_ssm(aws, value=stored)
    assert_911_from(call(event(auth=basic(stored))), caplog, "ValueError")


def test_stored_credential_trailing_newline_is_ignored(aws):
    # Bug caught: a parameter created from a file (value ends in "\n") rejecting the right password.
    expect_ssm(aws, value=CREDS + "\n")
    expect_read(aws, ["93.184.216.34"])
    assert call(event())["body"] == "nochg 93.184.216.34"


def test_lowercase_basic_scheme_is_accepted(aws):
    # Bug caught: a case-sensitive scheme check rejecting clients that send "basic" (RFC 7617).
    expect_ssm(aws)
    expect_read(aws, ["93.184.216.34"])
    assert call(event(auth="basic " + basic(CREDS).split()[1]))["body"] == "nochg 93.184.216.34"


# --- hostname ---------------------------------------------------------------

@pytest.mark.parametrize(
    "query",
    [
        "hostname=other.example.com&myip=93.184.216.34",
        "hostname=home.example.com.evil.net&myip=93.184.216.34",
        "myip=93.184.216.34",
        "hostname=home.example.com&hostname=other.example.com&myip=93.184.216.34",
    ],
)
def test_wrong_or_ambiguous_hostname_is_nohost_without_write(aws, query):
    # Bug caught: suffix/prefix matching or a duplicated parameter letting a caller target
    # a name other than RecordName.
    expect_ssm(aws)
    resp = call(event(query=query))
    assert (resp["statusCode"], resp["body"]) == (200, "nohost")


def test_hostname_match_is_case_insensitive_and_ignores_trailing_dot(aws):
    # Bug caught: inadyn/UniFi sending "Home.Example.COM." being rejected as nohost.
    expect_ssm(aws)
    expect_read(aws, ["93.184.216.34"])
    assert call(event(query="hostname=Home.Example.COM.&myip=93.184.216.34"))["body"] == "nochg 93.184.216.34"


# --- ip selection -----------------------------------------------------------

@pytest.mark.parametrize("myip", ["192.168.1.10", "10.0.0.1", "100.64.0.1", "127.0.0.1", "not-an-ip",
                                  "2001:db8::1", "", "93.184.216.034", "224.0.0.1", "239.255.255.250",
                                  "203.0.113.7", "255.255.255.255"])
def test_invalid_or_private_myip_falls_back_to_source_ip(aws, myip, capsys):
    # Bug caught: publishing a LAN/CGNAT/garbage address (UniFi behind double NAT reports the
    # WAN-interface address) instead of the public source IP.
    expect_ssm(aws)
    expect_read(aws, ["34.120.0.1"])
    expect_upsert(aws, "52.94.10.20")
    resp = call(event(query=f"hostname=home.example.com&myip={myip}"))
    assert (resp["statusCode"], resp["body"]) == (200, "good 52.94.10.20")
    assert log_lines(capsys)[-1]["ip_source"] == "sourceIp"


def test_whitespace_padded_myip_is_used(aws):
    # Bug caught: "myip=+1.2.3.4" (decoded as " 1.2.3.4") being discarded for the source IP.
    expect_ssm(aws)
    expect_read(aws, ["93.184.216.34"])
    assert call(event(query="hostname=home.example.com&myip=+93.184.216.34+"))["body"] == "nochg 93.184.216.34"


def test_no_global_ip_anywhere_is_rejected_without_write(aws):
    # Bug caught: writing a private source IP when myip is also unusable.
    expect_ssm(aws)
    resp = call(event(query="hostname=home.example.com&myip=10.1.1.1", source_ip="10.2.2.2"))
    assert (resp["statusCode"], resp["body"]) == (400, "badip")


# --- record update ----------------------------------------------------------

def test_nochg_when_record_already_holds_ip(aws):
    # Bug caught: an UPSERT on every check-in (inadyn polls every few minutes).
    expect_ssm(aws)
    expect_read(aws, ["93.184.216.34"])
    resp = call(event())
    assert (resp["statusCode"], resp["body"]) == (200, "nochg 93.184.216.34")


def test_good_path_upserts_and_logs_without_secrets(aws, capsys):
    # Bug caught: wrong record/TTL in the change batch, or the credential/header/query string
    # leaking into CloudWatch Logs.
    expect_ssm(aws)
    expect_read(aws, ["34.120.0.1"])
    expect_upsert(aws, "93.184.216.34")
    resp = call(event())
    assert (resp["statusCode"], resp["body"]) == (200, "good 93.184.216.34")
    out = capsys.readouterr()
    record = json.loads(out.out.splitlines()[-1])
    assert record == {"request_id": "req-1", "hostname": "home.example.com", "ip": "93.184.216.34",
                      "ip_source": "myip", "result": "good"}
    logged = out.out + out.err
    for secret in ("s3cret-pass", basic(CREDS).split()[1], "myip="):
        assert secret not in logged


@pytest.mark.parametrize("values,ttl", [(None, None), (["93.184.216.34", "34.120.0.1"], 60), (["93.184.216.34"], 300)])
def test_missing_multivalue_or_stale_ttl_record_is_written(aws, values, ttl):
    # Bug caught: treating "record contains the IP" as up to date when it has extra values or
    # the wrong TTL, or crashing when the record does not exist yet.
    expect_ssm(aws)
    expect_read(aws, values, ttl=ttl)
    expect_upsert(aws, "93.184.216.34")
    assert call(event())["body"] == "good 93.184.216.34"


def test_neighbouring_record_is_not_mistaken_for_ours(aws):
    # Bug caught: ListResourceRecordSets returns the next name in the zone when ours is absent;
    # comparing against it could report nochg for a record that does not exist.
    expect_ssm(aws)
    expect_read(aws, ["93.184.216.34"], name="www.example.com.")
    expect_upsert(aws, "93.184.216.34")
    assert call(event())["body"] == "good 93.184.216.34"


def test_route53_write_failure_returns_911(aws):
    # Bug caught: reporting "good" when the UPSERT was rejected.
    expect_ssm(aws)
    expect_read(aws, ["34.120.0.1"])
    aws.r53.add_client_error("change_resource_record_sets", service_error_code="AccessDenied", http_status_code=403)
    assert call(event())["body"] == "911"


def test_911_log_line_is_bare_json_for_the_metric_filter(aws, capsys):
    # Bug caught: the 911 line carrying a runtime prefix ("[ERROR]\t...") or not being JSON, so
    # the template's { $.result = "911" } metric filter never matches and the alarm stays silent.
    aws.ssm.add_client_error("get_parameter", service_error_code="ThrottlingException", http_status_code=400)
    call(event())
    assert log_lines(capsys)[-1]["result"] == "911"


@pytest.mark.parametrize(
    "rrset",
    [
        {"Name": FQDN, "Type": "A", "AliasTarget": {"HostedZoneId": "Z2FDTNDATAQYW2",
                                                    "DNSName": "d111.cloudfront.net.", "EvaluateTargetHealth": False}},
        {"Name": FQDN, "Type": "A", "SetIdentifier": "primary", "Weight": 10, "TTL": 60,
         "ResourceRecords": [{"Value": "34.120.0.1"}]},
        {"Name": FQDN, "Type": "CNAME", "TTL": 60, "ResourceRecords": [{"Value": "elsewhere.example.net"}]},
    ],
)
def test_conflicting_record_at_name_is_not_overwritten(aws, rrset, caplog):
    # Bug caught: an UPSERT silently replacing an alias record, or looping on a write that
    # Route 53 will always reject (CNAME / routing-policy record at the name).
    expect_ssm(aws)
    expect_read_raw(aws, rrset)
    assert_911_from(call(event()), caplog, "ConflictingRecordError")


class _Clock(SimpleNamespace):
    def get_remaining_time_in_millis(self):
        return self.remaining


def test_aws_call_not_started_without_time_budget(aws, capsys, caplog):
    # Bug caught: starting an AWS call that can outlive the function timeout, which turns into
    # an unlogged 502 instead of a logged 911. No SSM response is queued: the call must not happen.
    resp = app.handler(event(), _Clock(aws_request_id="req-2", remaining=6000))
    assert_911_from(resp, caplog, "TimeoutError")
    assert log_lines(capsys)[-1]["result"] == "911"


# --- routing ----------------------------------------------------------------

def test_non_get_and_other_paths_rejected_before_auth(aws):
    # Bug caught: the endpoint acting on POSTs or arbitrary paths.
    assert call(event(method="POST"))["statusCode"] == 405
    assert call(event(path="/"))["statusCode"] == 404
