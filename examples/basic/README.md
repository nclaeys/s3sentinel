# Basic example

This example runs the full s3sentinel stack locally using Docker Compose. By the end you will have:

- an admin user who can upload and read files
- a reader user who can read files but is blocked from uploading
- a bucket with a test object already in it

## Services

| Service | Port | Purpose |
|---|---|---|
| s3sentinel proxy | `8080` | The S3-compatible proxy — point your client here |
| s3sentinel STS | `8090` | Credential vending (`AssumeRoleWithWebIdentity`) |
| s3sentinel admin | `9090` | `/healthz`, `/readyz`, `/metrics` |
| Keycloak | `8180` | OIDC identity provider |
| MinIO S3 | `9000` | Local S3 backend |
| MinIO console | `9001` | MinIO web UI |
| OPA | `8181` | Policy engine |

## Users

| Username | Password | Group | Can upload? | Can read? |
|---|---|---|---|---|
| `admin` | `admin123` | admin | yes | yes |
| `reader` | `reader123` | reader | no | yes |

## Prerequisites

- Docker and Docker Compose v2
- `curl` and `jq` for the walkthrough commands below
- Python 3 + `boto3` for the Python examples (`pip install boto3`)

## Start the stack

Run from the **project root** (the directory containing `go.mod`):

```bash
docker compose -f examples/basic/docker-compose.yml up --build
```

Keycloak takes roughly 30–60 seconds to start on first run. Wait until you see all services report healthy:

```bash
# In a second terminal — poll until every service is up
docker compose -f examples/basic/docker-compose.yml ps
```

Confirm s3sentinel is ready:

```bash
curl -s http://localhost:9090/readyz | jq .
# {"jwks":{"status":"ok"},"opa":{"status":"ok"}}
```

---

## Walkthrough

### Step 1 — obtain tokens

Fetch an access token for each user from Keycloak:

```bash
ADMIN_TOKEN=$(curl -s -X POST \
  http://localhost:8180/realms/s3sentinel/protocol/openid-connect/token \
  -d grant_type=client_credentials \
  -d client_id=s3sentinel \
  -d username=admin \
  -d password=admin123 \
  -d grant_type=password \
  | jq -r .access_token)

READER_TOKEN=$(curl -s -X POST \
  http://localhost:8180/realms/s3sentinel/protocol/openid-connect/token \
  -d grant_type=client_credentials \
  -d client_id=s3sentinel \
  -d username=reader \
  -d password=reader123 \
  -d grant_type=password \
  | jq -r .access_token)
```

Verify the tokens look right (non-empty):

```bash
echo $ADMIN_TOKEN | cut -c1-20   # should start with "eyJ..."
echo $READER_TOKEN | cut -c1-20
```

---

### Step 2 — admin uploads a file

```bash
echo "quarterly sales data" > /tmp/report.csv

curl -s -X PUT http://localhost:8080/example-bucket/reports/report.csv \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: text/csv" \
  --data-binary @/tmp/report.csv

echo "exit code: $?"   # 0 = success
```

Confirm the object exists by listing the prefix:

```bash
curl -s "http://localhost:8080/example-bucket?list-type=2&prefix=reports/" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

---

### Step 3 — reader downloads the file

```bash
curl -s http://localhost:8080/example-bucket/reports/report.csv \
  -H "Authorization: Bearer $READER_TOKEN"
# quarterly sales data
```

---

### Step 4 — reader is blocked from uploading

```bash
curl -s -o /dev/null -w "%{http_code}" \
  -X PUT http://localhost:8080/example-bucket/reports/malicious.csv \
  -H "Authorization: Bearer $READER_TOKEN" \
  -H "Content-Type: text/csv" \
  --data-binary "this should not be allowed"
# 403
```

The proxy returns `403 AccessDenied`. The `PutObject` action is not in the reader policy, so OPA denies it regardless of the path.

---

## Same scenario using STS credentials (boto3)

The STS flow exchanges the OIDC token for short-lived AWS-compatible credentials. After the exchange, boto3 works with no custom headers.

```python
import boto3
from botocore.exceptions import ClientError
import urllib.request, urllib.parse, json

KEYCLOAK = "http://localhost:8180/realms/s3sentinel/protocol/openid-connect/token"
PROXY     = "http://localhost:8080"
STS       = "http://localhost:8090"


def get_token(username, password):
    data = urllib.parse.urlencode({
        "grant_type": "password",
        "client_id":  "s3sentinel",
        "username":   username,
        "password":   password,
    }).encode()
    with urllib.request.urlopen(KEYCLOAK, data) as r:
        return json.load(r)["access_token"]


def assume_role(token):
    """Exchange an OIDC token for temporary S3 credentials via STS."""
    sts = boto3.client(
        "sts",
        endpoint_url=STS,
        aws_access_key_id="placeholder",
        aws_secret_access_key="placeholder",
        region_name="us-east-1",
    )
    resp = sts.assume_role_with_web_identity(
        RoleArn="arn:aws:iam::000000000000:role/s3sentinel",
        RoleSessionName="example",
        WebIdentityToken=token,
    )
    return resp["Credentials"]


def s3_client(creds):
    return boto3.client(
        "s3",
        endpoint_url=PROXY,
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name="us-east-1",
    )


# ── Admin: upload a file ──────────────────────────────────────────────────────
admin_creds = assume_role(get_token("admin", "admin123"))
admin_s3    = s3_client(admin_creds)

admin_s3.put_object(
    Bucket="example-bucket",
    Key="reports/report.csv",
    Body=b"quarterly sales data",
)
print("admin upload: OK")

# ── Reader: download the file ─────────────────────────────────────────────────
reader_creds = assume_role(get_token("reader", "reader123"))
reader_s3    = s3_client(reader_creds)

obj = reader_s3.get_object(Bucket="example-bucket", Key="reports/report.csv")
print("reader download:", obj["Body"].read().decode())

# ── Reader: upload blocked ────────────────────────────────────────────────────
try:
    reader_s3.put_object(
        Bucket="example-bucket",
        Key="reports/malicious.csv",
        Body=b"this should not be allowed",
    )
    print("reader upload: ERROR — should have been denied")
except ClientError as e:
    print("reader upload blocked:", e.response["Error"]["Code"])  # AccessDenied
```

Run it:

```bash
python3 examples/basic/demo.py
# admin upload: OK
# reader download: quarterly sales data
# reader upload blocked: AccessDenied
```

---

## Inspecting the SessionToken

When you call `AssumeRoleWithWebIdentity` the STS server returns a `SessionToken`. This token is a signed JWT (HS256) that encodes the caller's identity. The proxy validates it on every request without contacting the IdP — all the information it needs is inside the token.

### Reading the claims (no secret required)

A JWT is three base64url-encoded segments separated by dots: `header.payload.signature`. You can decode the payload with nothing but standard shell tools:

```bash
# Fetch credentials for the reader user
SESSION_TOKEN=$(curl -s -X POST \
  'http://localhost:8090/?Action=AssumeRoleWithWebIdentity&Version=2011-06-15' \
  --data-urlencode "WebIdentityToken=$READER_TOKEN" \
  --data-urlencode "RoleArn=arn:aws:iam::000000000000:role/s3sentinel" \
  --data-urlencode "RoleSessionName=inspect-demo" \
  | grep -o '<SessionToken>[^<]*' | sed 's/<SessionToken>//')

# Decode the payload segment (middle part of the JWT)
echo $SESSION_TOKEN \
  | cut -d. -f2 \
  | tr '_-' '/+' \
  | base64 -d 2>/dev/null \
  | jq .
```

Example output:

```json
{
  "iss": "s3sentinel-sts",
  "sub": "reader",
  "iat": 1744070400,
  "exp": 1744074000,
  "email": "reader@example.com",
  "groups": ["reader"]
}
```

| Claim | Meaning |
|---|---|
| `iss` | Always `s3sentinel-sts` — distinguishes these tokens from OIDC tokens |
| `sub` | The user's identity sent to OPA as `input.principal` |
| `email` | The user's email sent to OPA as `input.email` |
| `groups` | The user's group memberships sent to OPA as `input.groups` |
| `iat` | Issued-at time (Unix timestamp) |
| `exp` | Expiry time — after this the proxy rejects the token with `401` |

### Verifying the signature (requires the secret)

Reading the payload above requires no secret — anyone who holds the token can see the claims. The HMAC signature on the third segment is what prevents tampering: a client cannot change their `groups` claim and re-sign the token without knowing `STS_TOKEN_SECRET`.

To verify locally using Python:

```python
import base64, hashlib, hmac, json

SECRET = b"dev-only-change-this-secret-in-production"  # matches docker-compose.yml

def verify_session_token(token: str) -> dict:
    header_b64, payload_b64, sig_b64 = token.split(".")
    signing_input = f"{header_b64}.{payload_b64}".encode()

    # Re-compute the expected signature
    expected = hmac.new(SECRET, signing_input, hashlib.sha256).digest()
    expected_b64 = base64.urlsafe_b64encode(expected).rstrip(b"=")

    received = sig_b64.encode()
    if not hmac.compare_digest(expected_b64, received):
        raise ValueError("signature verification failed — token has been tampered with")

    # Decode the payload
    padding = 4 - len(payload_b64) % 4
    payload = base64.urlsafe_b64decode(payload_b64 + "=" * padding)
    return json.loads(payload)

claims = verify_session_token(SESSION_TOKEN)
print(claims["sub"])     # reader
print(claims["groups"])  # ['reader']
```

In production the proxy performs this verification on every S3 request using Go's `crypto/hmac` package. If the signature check fails — or if `exp` is in the past — the request is rejected with `401 InvalidToken` before OPA is ever consulted.

---

## Verify the policy directly

You can query OPA directly to understand why a request was allowed or denied:

```bash
# Should return true — admin reading an object
curl -s -X POST http://localhost:8181/v1/data/s3/allow \
  -H "Content-Type: application/json" \
  -d '{"input":{"principal":"admin","groups":["admin"],"action":"PutObject","bucket":"example-bucket","key":"reports/report.csv"}}' \
  | jq .result
# true

# Should return false — reader writing an object
curl -s -X POST http://localhost:8181/v1/data/s3/allow \
  -H "Content-Type: application/json" \
  -d '{"input":{"principal":"reader","groups":["reader"],"action":"PutObject","bucket":"example-bucket","key":"reports/report.csv"}}' \
  | jq .result
# false
```

## Check the MinIO console

Open [http://localhost:9001](http://localhost:9001) and log in with `minioadmin / minioadmin`. You can browse `example-bucket` and see the objects written by the admin user.

---

## Stop the stack

```bash
docker compose -f examples/basic/docker-compose.yml down
```

To also remove the MinIO data volume:

```bash
docker compose -f examples/basic/docker-compose.yml down -v
```
