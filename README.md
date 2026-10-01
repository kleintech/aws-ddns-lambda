# aws-ddns-lambda

A minimal, hardened dynamic DNS endpoint for Route 53, built for the UniFi Dream
Machine's built-in DDNS client (inadyn, "custom" provider).

- One hostname, one A record. No IPv6, no multiple hosts, no custom endpoint domain.
- AWS Lambda (Python 3.13, arm64, 128 MB, 10 s) behind a **Function URL**. No API
  Gateway, no ACM, no bundled dependencies (boto3 comes from the runtime).
- dyndns2-style API: `GET /nic/update?hostname=<fqdn>&myip=<ipv4>` with HTTP Basic auth.

## How it behaves

| Situation | HTTP | Body |
|---|---|---|
| Record updated | 200 | `good <ip>` |
| Record already holds the IP (and TTL) — no write | 200 | `nochg <ip>` |
| Missing / wrong credentials | 401 + `WWW-Authenticate: Basic` | `badauth` |
| `hostname` missing, repeated, or not the configured record | 200 | `nohost` |
| Neither `myip` nor the request source is a public IPv4 | 400 | `badip` |
| Internal error (SSM, Route 53, a conflicting record at the name, out of time) | 500 | `911` |
| Not `GET` / not `/nic/update` | 405 / 404 | `badrequest` / `notfound` |

**IP selection.** `myip` is used if it is a valid, globally routable IPv4 address.
Otherwise the request's source IP (as seen by the Function URL) is used if it is
global. Otherwise the request is rejected. RFC 1918, CGNAT (100.64/10), loopback,
multicast, documentation and other non-global ranges are never published. Function
URLs are dual-stack: if the UDM reaches the endpoint over IPv6 *and* `myip` is unusable,
the result is `badip` (normally UniFi fills `%i` with the WAN IPv4 address). The log line says
which source was used (`ip_source`: `myip` or `sourceIp`).

**Writes.** The current record is read first; if it already holds exactly that one
IP with the configured TTL, nothing is written. Otherwise a single `UPSERT` is sent.
The function does not wait for the change to reach `INSYNC`. If the name already holds
an alias A record, a weighted/latency/etc. A record, or a CNAME, the function refuses to
touch it and returns `911` (and alarms) rather than silently replacing it.

**Auth.** The `user:pass` pair lives in an SSM SecureString. It is read once per
cold start and cached in memory; comparison uses `hmac.compare_digest`. Requests
without a well-formed `Authorization: Basic` header are rejected before anything
else is touched.

**Logging.** One bare JSON line per request on stdout with `request_id`, `hostname`,
`ip`, `ip_source`, `result` (bare JSON so the alarm's `{ $.result = "911" }` metric
filter can match it). The Authorization header, the password and the raw query
string are never logged. Logs go to `/aws/lambda/<stack-name>` with 30-day retention.

**Abuse throttle.** `ReservedConcurrentExecutions: 2`. Requests beyond 2 concurrent
executions, or beyond 10 × reserved concurrency = 20 requests/second, get HTTP 429 from
Lambda without running the function. That caps the cost of a flood per second, not in
total, and a sustained flood also crowds out the UDM's own updates (inadyn retries).
Unauthenticated requests never touch Route 53; they only cost an invocation and a log
line. If that worries you, add an AWS Budgets alert; CloudFront + WAF rate limiting is
the heavier fix and out of scope here.

## Verified compatibility notes

Checked against the sources rather than assumed:

- **inadyn sends Basic auth from the UniFi Username/Password fields.** The custom
  provider's request template hard-codes `Authorization: Basic %s`, filled from
  `username:password` base64-encoded for every provider
  ([plugins/generic.c](https://github.com/troglobit/inadyn/blob/98e43d7db4b9c8e0989a790dda435075f4f78770/plugins/generic.c#L35-L40),
  `get_encoded_user_passwd()` in
  [src/ddns.c](https://github.com/troglobit/inadyn/blob/98e43d7db4b9c8e0989a790dda435075f4f78770/src/ddns.c)).
  The header is sent pre-emptively; inadyn never waits for a 401 challenge.
- **inadyn treats `nochg` as success**, so the endpoint returns `nochg <ip>` as-is. The
  generic plugin's `response()` first requires HTTP 200, then does a case-insensitive
  substring match against `OK good true updated success nochg`
  ([plugins/generic.c](https://github.com/troglobit/inadyn/blob/98e43d7db4b9c8e0989a790dda435075f4f78770/plugins/generic.c#L42-L43),
  [L246-262](https://github.com/troglobit/inadyn/blob/98e43d7db4b9c8e0989a790dda435075f4f78770/plugins/generic.c#L246-L262)).
  401/403 are treated as auth failures, 5xx as "retry later". None of the failure
  bodies here contain a success substring.
- **HTTPS.** inadyn's `ssl` option defaults to true for custom providers, and UniFi's
  generated config omits it, so requests go to port 443 with SNI and certificate
  verification. Confirm with `grep ssl /run/ddns-*-inadyn.conf` (absent or `true`).
- **Public Function URL permissions.** Since October 2025 a public (AuthType `NONE`)
  URL needs both `lambda:InvokeFunctionUrl` (with `FunctionUrlAuthType: NONE`) and
  `lambda:InvokeFunction` (with `InvokedViaFunctionUrl: true`), else every request is
  403 ([docs](https://docs.aws.amazon.com/lambda/latest/dg/urls-auth.html)). The
  template declares both explicitly.
- **No `kms:Decrypt` needed** for a SecureString under the AWS managed key `aws/ssm`:
  its key policy already allows use via SSM by principals in the account
  ([docs](https://docs.aws.amazon.com/systems-manager/latest/userguide/sysman-paramstore-access.html)).
  A customer managed key *would* need `kms:Decrypt` added to the role.
- **SNS topic is not KMS-encrypted** on purpose: CloudWatch alarms can't publish to a
  topic encrypted with `aws/sns`
  ([docs](https://docs.aws.amazon.com/sns/latest/dg/sns-key-management.html)), and the
  messages carry no secrets.

## Deploy

Prerequisites: AWS CLI v2, SAM CLI, and credentials from **IAM Identity Center (SSO)
or a named profile** — don't create long-lived access keys for this.

```sh
export AWS_PROFILE=<your-profile>      # e.g. after `aws sso login --profile <your-profile>`
export AWS_REGION=<region>             # e.g. us-east-1
```

### 1. Create the credential parameter

CloudFormation cannot create SecureString parameters, so create it with the CLI. Pick
a username and a long random password (the UDM stores it; you never type it again):

```sh
DDNS_USER=udm
DDNS_PASS=$(openssl rand -base64 32 | tr -d '/+=' | cut -c1-32)
echo "password: $DDNS_PASS"            # copy into the UniFi Password field

aws ssm put-parameter \
  --name /route53-ddns/credentials \
  --type SecureString \
  --value "$DDNS_USER:$DDNS_PASS"
```

This uses the AWS managed key `aws/ssm` (the default). Avoid characters in the
password that UniFi or inadyn might mangle; alphanumerics are safest. A trailing newline
in the stored value is ignored; leading/trailing spaces are not.

To rotate later, re-run `put-parameter ... --overwrite`. Warm Lambda instances keep the
old value cached until they are recycled; force that immediately with:

```sh
aws lambda update-function-configuration --function-name <FunctionName output> \
  --description "rotated $(date -u +%FT%TZ)"
```

### 2. Build and deploy

```sh
sam build
sam deploy --guided
```

`--guided` asks for the parameters and saves your answers to `samconfig.toml`, which
is git-ignored on purpose: it holds account-specific values. Parameters:

| Parameter | Meaning |
|---|---|
| `HostedZoneId` | Public hosted zone containing the record, e.g. `Z0123456789ABC` |
| `RecordName` | The FQDN to manage, lowercase, no trailing dot, e.g. `home.example.com` |
| `Ttl` | Record TTL in seconds (default 60) |
| `CredentialParamName` | SSM parameter from step 1 (default `/route53-ddns/credentials`) |
| `AlarmEmail` | Optional. If set: an SNS topic (confirm the subscription email) and an alarm when, over one hour, the function errors or returns `911` |

The stack outputs `FunctionUrl`, e.g.
`https://abcdefghijklmnop.lambda-url.us-east-1.on.aws/`.

`ReservedConcurrentExecutions` needs the account's *unreserved* concurrency to stay at
least 100 after reserving 2. Check with `aws lambda get-account-settings`; new accounts
sometimes start with a limit of 10, in which case the deploy fails until you request a
quota increase (or remove that line).

### 3. Test

In a new shell, read the credentials back first:

```sh
CRED=$(aws ssm get-parameter --name /route53-ddns/credentials --with-decryption --query Parameter.Value --output text)
DDNS_USER=${CRED%%:*}; DDNS_PASS=${CRED#*:}
URL=https://abcdefghijklmnop.lambda-url.us-east-1.on.aws
curl -s -u "$DDNS_USER:$DDNS_PASS" "$URL/nic/update?hostname=home.example.com&myip=1.2.3.4"   # good 1.2.3.4
curl -s -u "$DDNS_USER:$DDNS_PASS" "$URL/nic/update?hostname=home.example.com&myip=1.2.3.4"   # nochg 1.2.3.4
curl -s -u "$DDNS_USER:wrong"      "$URL/nic/update?hostname=home.example.com"                # badauth (401)
curl -s -u "$DDNS_USER:$DDNS_PASS" "$URL/nic/update?hostname=other.example.com"               # nohost
curl -s -u "$DDNS_USER:$DDNS_PASS" "$URL/nic/update?hostname=home.example.com"                # good/nochg <your public IP>
```

## UniFi configuration

Settings → Internet → (WAN) → Dynamic DNS → Create New:

| Field | Value |
|---|---|
| Service | `custom` |
| Hostname | `home.example.com` |
| Username | the `DDNS_USER` value |
| Password | the `DDNS_PASS` value |
| Server | `abcdefghijklmnop.lambda-url.us-east-1.on.aws/nic/update?hostname=%h&myip=%i` |

The Server field takes the host and path **without** `https://`.

Check it from the UDM over SSH:

```sh
ls /run/ddns-*-inadyn.conf
inadyn -1 --force -l debug -f /run/ddns-<iface>-inadyn.conf
```

## IAM

The function's role allows only:

- `route53:ChangeResourceRecordSets` on the one hosted zone, conditioned on
  `ChangeResourceRecordSetsNormalizedRecordNames = [RecordName]`,
  `ChangeResourceRecordSetsRecordTypes = [A]`, `ChangeResourceRecordSetsActions = [UPSERT]`.
- `route53:ListResourceRecordSets` on that zone.
- `ssm:GetParameter` on the one parameter ARN.
- `logs:CreateLogStream` / `logs:PutLogEvents` on its own log group.

## Development

```sh
uv venv -p 3.13 .venv && uv pip install -p .venv boto3 pytest
.venv/bin/pytest -q          # botocore Stubber, no network
sam validate --lint
```

## Removing it

```sh
sam delete
aws ssm delete-parameter --name /route53-ddns/credentials
```

The A record itself is left in place.
