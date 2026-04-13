# S3 Fine-Grained Access Proxy

An S3-compatible reverse proxy that adds identity-aware, policy-driven access control on top of EU cloud object storage (OVHcloud, Scaleway, Exoscale, Hetzner, …).

EU cloud providers issue bucket-level service-account credentials only — there is no IAM, no STS, no resource-level policies. This proxy sits in front of your bucket, owns the service-account key, and gates every S3 operation through [OPA](https://www.openpolicyagent.org/) using the caller's OIDC identity.

Two authentication flows are supported:

**Flow A — Direct JWT** (simple setup, custom SDK integration required)
```
Client ──[Authorization: Bearer <OIDC JWT>]──► Proxy :8080
                                                 ├─ Validate JWT (JWKS)
                                                 ├─ Check OPA
                                                 ├─ Re-sign → OVH S3
                                                 └─ Stream response back
```

**Flow B — STS credential vending** (standard AWS SDK integration, no custom headers)
```
Client ──[WebIdentityToken=<OIDC JWT>]──► STS :8090
                                            └─ Validate JWT → issue temp credentials
                                               (AccessKeyID + SecretKey + SessionToken)

Client ──[AWS SigV4 + X-Amz-Security-Token]──► Proxy :8080
                                                  ├─ Validate SessionToken (HMAC JWT)
                                                  ├─ Check OPA
                                                  ├─ Re-sign → OVH S3
                                                  └─ Stream response back
```

Flow B is compatible with every AWS SDK out of the box — boto3, AWS CLI, Spark, DuckDB, Terraform S3 backends, and others all support `AssumeRoleWithWebIdentity` natively.

## Prerequisites

| Tool | Minimum version | Install |
|---|---|---|
| Go | 1.22 | <https://go.dev/dl/> |
| OPA | 0.65 | `brew install opa` or [download](https://github.com/open-policy-agent/opa/releases) |
| An OVH Object Storage bucket | — | OVH Control Panel |
| An OIDC-capable IdP | — | Keycloak, Dex, Auth0, Google, … |

---

## 1  OVH Object Storage — get your credentials

### 1a  Find your endpoint and region

In the OVH Control Panel, go to **Public Cloud → Object Storage → your container** and note:

- **Region** — shown in the container list (e.g. `GRA`, `SBG`, `WAW`). The proxy uses the lowercase form: `gra`, `sbg`, `waw`.
- **Endpoint** — the S3-compatible URL for that region:

  | Region | Endpoint |
  |---|---|
  | GRA (Gravelines) | `https://s3.gra.io.cloud.ovh.net` |
  | SBG (Strasbourg) | `https://s3.sbg.io.cloud.ovh.net` |
  | WAW (Warsaw) | `https://s3.waw.io.cloud.ovh.net` |
  | BHS (Beauharnois) | `https://s3.bhs.io.cloud.ovh.net` |

### 1b  Create S3 credentials

The proxy uses a single service-account key pair with full bucket access. Clients never see it.

1. In the OVH Control Panel open **Public Cloud → Users & Roles → Users**.
2. Create a user (or use an existing one) with the **ObjectStore operator** role.
3. Click the user → **S3 credentials** tab → **Generate credentials**.
4. Save the **Access key** and **Secret key** — they are shown only once.

---

## 2  OPA — write a policy

OPA runs as a sidecar. The proxy POSTs every request to OPA before forwarding it.

### 2a  Policy input shape

```json
{
  "input": {
    "principal": "alice@example.com",
    "email":     "alice@example.com",
    "groups":    ["data-engineers", "eu-west"],
    "action":    "GetObject",
    "bucket":    "my-bucket",
    "key":       "datasets/sales/2024.parquet"
  }
}
```

`action` is one of the S3 API operation names: `GetObject`, `PutObject`, `DeleteObject`, `ListObjects`, `ListObjectsV2`, `HeadObject`, `CopyObject`, `CreateMultipartUpload`, `UploadPart`, `CompleteMultipartUpload`, `AbortMultipartUpload`, `GetBucketAcl`, `DeleteObjects`, and so on.

### 2b  Create `policy/s3.rego`

```bash
mkdir -p policy
```

```rego
# policy/s3.rego
package s3

import rego.v1

# Deny everything by default.
default allow := false

# Data engineers can read anything.
allow if {
    input.action in {"GetObject", "HeadObject", "ListObjects", "ListObjectsV2"}
    input.groups[_] == "data-engineers"
}

# Data engineers can write to the raw/ prefix only.
allow if {
    input.action in {"PutObject", "DeleteObject", "CreateMultipartUpload",
                     "UploadPart", "CompleteMultipartUpload", "AbortMultipartUpload"}
    input.groups[_] == "data-engineers"
    startswith(input.key, "raw/")
}

# Admins can do everything.
allow if {
    input.groups[_] == "admins"
}
```

### 2c  Start OPA

```bash
opa run --server --addr :8181 policy/
```

OPA is now listening on `http://localhost:8181`. The proxy will call:

```
POST http://localhost:8181/v1/data/s3/allow
```

Verify your policy works before starting the proxy:

```bash
curl -s -X POST http://localhost:8181/v1/data/s3/allow \
  -H 'Content-Type: application/json' \
  -d '{
    "input": {
      "principal": "alice",
      "groups": ["data-engineers"],
      "action": "GetObject",
      "bucket": "my-bucket",
      "key": "datasets/report.csv"
    }
  }' | jq .
# → {"result":true}
```

---

## 3  Build and configure the proxy

### 3a  Build

```bash
git clone https://github.com/dataminded/s3sentinel.git
cd s3sentinel
go build -o s3sentinel ./cmd/s3sentinel
```

### 3b  Create `.env`

```bash
cp .env.example .env
```

Edit `.env` with your values:

```dotenv
# ── Proxy ──────────────────────────────────────────────────────────────────
LISTEN_ADDR=:8080

# ── OVH Object Storage ─────────────────────────────────────────────────────
BACKEND_ENDPOINT=https://s3.gra.io.cloud.ovh.net   # change region as needed
BACKEND_REGION=gra
BACKEND_ACCESS_KEY=<your-ovh-s3-access-key>
BACKEND_SECRET_KEY=<your-ovh-s3-secret-key>

# ── OPA ────────────────────────────────────────────────────────────────────
OPA_ENDPOINT=http://localhost:8181/v1/data/s3/allow

# ── OIDC / JWT ─────────────────────────────────────────────────────────────
# JWKS URI from your IdP's discovery document (.well-known/openid-configuration)
JWKS_ENDPOINT=https://your-idp.example.com/.well-known/jwks.json
JWT_ISSUER=https://your-idp.example.com
JWT_AUDIENCE=s3sentinel          # comma-separated if multiple; leave blank to skip
```

### 3c  Enable STS credential vending (optional)

The STS server is off by default. To enable it, set `STS_TOKEN_SECRET` to a random HMAC key. This key signs and validates the `SessionToken` JWTs the STS server issues to clients — keep it secret and treat it like a password.

**Generate a key:**

```bash
# 32 random bytes, hex-encoded — copy the output into your .env
openssl rand -hex 32
# example output: a3f1c2d9e4b57608f0e1d2c3b4a5961728394e5f6071829a0b1c2d3e4f50617
```

**Add to `.env`:**

```dotenv
# ── STS credential vending ─────────────────────────────────────────────────
STS_TOKEN_SECRET=a3f1c2d9e4b57608f0e1d2c3b4a5961728394e5f6071829a0b1c2d3e4f50617
STS_LISTEN_ADDR=:8090          # address the STS endpoint listens on
STS_TOKEN_TTL=1h               # how long issued credentials stay valid (e.g. 30m, 2h)
```

When `STS_TOKEN_SECRET` is set the proxy starts a second HTTP server on `STS_LISTEN_ADDR` that handles `AssumeRoleWithWebIdentity` requests. The main proxy on `:8080` simultaneously accepts both the direct JWT flow (Flow A) and STS-issued session tokens (Flow B).

### 3d  Start the proxy

```bash
set -a && source .env && set +a
./s3sentinel
# {"time":"...","level":"INFO","msg":"s3 proxy starting","addr":":8080","backend":"https://s3.gra.io.cloud.ovh.net","tls":false}
# {"time":"...","level":"INFO","msg":"sts server starting","addr":":8090","ttl":"1h0m0s"}   ← only if STS_TOKEN_SECRET is set
# {"time":"...","level":"INFO","msg":"admin server starting","addr":":9090"}
```

---

## 4  Call the proxy

There are two authentication flows. Choose based on your integration needs.

---

### Flow A — Direct JWT (curl / simple HTTP clients)

No STS required. Pass your OIDC token directly on every request.

```bash
# Obtain a token from your IdP:
TOKEN=$(curl -s -X POST https://your-idp.example.com/token \
  -d 'grant_type=password&client_id=s3sentinel&username=alice&password=...' \
  | jq -r .access_token)

# List objects
curl -s http://localhost:8080/my-bucket \
  -H "Authorization: Bearer $TOKEN"

# Download an object
curl -s http://localhost:8080/my-bucket/datasets/report.csv \
  -H "Authorization: Bearer $TOKEN" -o report.csv

# Upload an object
curl -s -X PUT http://localhost:8080/my-bucket/raw/upload.csv \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: text/csv" \
  --data-binary @upload.csv
```

For AWS SDK clients that cannot inject arbitrary headers, you can instead pass the JWT in the `X-Auth-Token` header (the proxy checks both). Configure the SDK with any fake access key / secret, point its `endpoint_url` at the proxy, and inject the header via your SDK's request hook mechanism.

---

### Flow B — STS credential vending (boto3, AWS CLI, Spark, DuckDB, …)

The client exchanges its OIDC JWT for short-lived AWS-compatible credentials once, then uses those credentials for all subsequent S3 requests. No custom headers or SDK hooks are needed — this is standard `AssumeRoleWithWebIdentity`.

#### Step 1 — exchange the JWT for temporary credentials

```bash
TOKEN=$(curl -s -X POST https://your-idp.example.com/token \
  -d 'grant_type=password&client_id=s3sentinel&username=alice&password=...' \
  | jq -r .access_token)

curl -s -X POST 'http://localhost:8090/?Action=AssumeRoleWithWebIdentity&Version=2011-06-15' \
  --data-urlencode "WebIdentityToken=$TOKEN" \
  --data-urlencode "RoleArn=arn:aws:iam::000000000000:role/s3sentinel" \
  --data-urlencode "RoleSessionName=my-session"
```

Response:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleWithWebIdentityResult>
    <Credentials>
      <AccessKeyId>ASIA3F9A1B2C3D4E5F6A</AccessKeyId>
      <SecretAccessKey>a1b2c3d4e5f6...</SecretAccessKey>
      <SessionToken>eyJhbGciOiJIUzI1NiJ9...</SessionToken>
      <Expiration>2024-01-01T01:00:00Z</Expiration>
    </Credentials>
    ...
  </AssumeRoleWithWebIdentityResult>
</AssumeRoleWithWebIdentityResponse>
```

#### Step 2 — use the credentials with any AWS SDK

**boto3**

```python
import boto3

TOKEN = "..."   # your OIDC JWT

# Exchange for temporary credentials
sts = boto3.client(
    "sts",
    endpoint_url="http://localhost:8090",
    aws_access_key_id="placeholder",       # required by boto3, not validated by STS
    aws_secret_access_key="placeholder",
    region_name="gra",
)
resp = sts.assume_role_with_web_identity(
    RoleArn="arn:aws:iam::000000000000:role/s3sentinel",
    RoleSessionName="my-session",
    WebIdentityToken=TOKEN,
)
creds = resp["Credentials"]

# Use the temporary credentials for S3 — no custom headers needed
s3 = boto3.client(
    "s3",
    endpoint_url="http://localhost:8080",
    aws_access_key_id=creds["AccessKeyId"],
    aws_secret_access_key=creds["SecretAccessKey"],
    aws_session_token=creds["SessionToken"],
    region_name="gra",
)

response = s3.list_objects_v2(Bucket="my-bucket", Prefix="datasets/")
for obj in response.get("Contents", []):
    print(obj["Key"])
```

**AWS CLI**

```bash
# Write a web identity token file (AWS CLI reads it automatically)
echo "$TOKEN" > /tmp/web-identity-token

# Configure a profile that uses web identity
cat >> ~/.aws/config <<'EOF'
[profile s3sentinel]
role_arn = arn:aws:iam::000000000000:role/s3sentinel
web_identity_token_file = /tmp/web-identity-token
sts_regional_endpoints = regional
EOF

# Use it — the CLI calls STS and refreshes credentials automatically
AWS_DEFAULT_REGION=gra \
  aws s3 ls s3://my-bucket/ \
  --profile s3sentinel \
  --endpoint-url http://localhost:8080 \
  --sts-endpoint-url http://localhost:8090
```

**DuckDB**

```sql
-- Install the httpfs extension first: INSTALL httpfs; LOAD httpfs;
CALL load_aws_credentials('s3sentinel');   -- picks up ~/.aws/config profile above

-- Or set credentials directly after fetching them via boto3 / curl:
SET s3_endpoint = 'localhost:8080';
SET s3_use_ssl = false;
SET s3_url_style = 'path';
SET s3_access_key_id     = 'ASIA3F9A1B2C3D4E5F6A';
SET s3_secret_access_key = 'a1b2c3d4e5f6...';
SET s3_session_token     = 'eyJhbGciOiJIUzI1NiJ9...';

SELECT * FROM read_parquet('s3://my-bucket/datasets/sales/2024.parquet');
```

---

## 5  Configuration reference

| Environment variable | Required | Default | Description |
|---|---|---|---|
| `LISTEN_ADDR` | no | `:8080` | Address and port the proxy listens on |
| `BACKEND_ENDPOINT` | **yes** | — | Full URL of the OVH S3 endpoint |
| `BACKEND_REGION` | no | `us-east-1` | S3 region sent in the SigV4 signature |
| `BACKEND_ACCESS_KEY` | **yes** | — | OVH service-account access key |
| `BACKEND_SECRET_KEY` | **yes** | — | OVH service-account secret key |
| `PROXY_HOST` | no | — | Proxy's own hostname for virtual-hosted-style detection (e.g. `s3.internal.example.com`) |
| `ADMIN_ADDR` | no | `:9090` | Address for the admin server (`/healthz`, `/readyz`, `/metrics`) |
| `TLS_CERT_FILE` | no | — | Path to PEM certificate file (or full chain). Both `TLS_CERT_FILE` and `TLS_KEY_FILE` must be set to enable HTTPS. |
| `TLS_KEY_FILE` | no | — | Path to PEM private key file. |
| `OPA_ENDPOINT` | **yes** | — | Full URL to the OPA rule, e.g. `http://opa:8181/v1/data/s3/allow` |
| `JWKS_ENDPOINT` | **yes** | — | JWKS URI from your IdP |
| `JWT_ISSUER` | no | — | Expected `iss` claim; omit to skip issuer validation |
| `JWT_AUDIENCE` | no | — | Comma-separated expected `aud` claims; omit to skip |
| `STS_TOKEN_SECRET` | no | — | HMAC key for signing/validating SessionToken JWTs. When set, the STS server starts and the proxy accepts session tokens. Generate with `openssl rand -hex 32`. |
| `STS_LISTEN_ADDR` | no | `:8090` | Address the STS server listens on (only used when `STS_TOKEN_SECRET` is set) |
| `STS_TOKEN_TTL` | no | `1h` | Lifetime of issued credentials. Go duration syntax: `30m`, `2h`, `24h`. |

### Enabling TLS

Set both `TLS_CERT_FILE` and `TLS_KEY_FILE` and the proxy switches from `ListenAndServe` to `ListenAndServeTLS`. Plain HTTP is used when either variable is absent. Setting only one is a startup error.

For local testing, generate a self-signed certificate:

```bash
openssl req -x509 -newkey rsa:4096 -sha256 -days 365 -nodes \
  -keyout key.pem -out cert.pem \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
```

Then in `.env`:

```dotenv
TLS_CERT_FILE=cert.pem
TLS_KEY_FILE=key.pem
```

For production, point the variables at certificates issued by your CA or managed by a tool such as [Certbot](https://certbot.eff.org/) / [cert-manager](https://cert-manager.io/). The proxy re-reads the certificate files on each new TLS handshake via Go's standard `tls.LoadX509KeyPair`, so certificate rotation does not require a restart as long as the file paths stay the same.

---

## 6  Observability

The proxy runs a second HTTP server on `ADMIN_ADDR` (default `:9090`) that exposes three endpoints. It is kept separate from the S3 port so that load-balancer health probes and Prometheus scrapes never pass through the OPA/JWT middleware.

### `/healthz` — liveness

Returns `200 OK` whenever the process is alive and can handle HTTP traffic. Use this as a Kubernetes `livenessProbe`.

```bash
curl http://localhost:9090/healthz
# {"status":"ok"}
```

### `/readyz` — readiness

Checks each dependency and returns `200 OK` only when all pass. Use this as a Kubernetes `readinessProbe`. If any check fails the response is `503 Service Unavailable`.

| Check | What it does |
|---|---|
| `opa` | `GET http://opa-host/health` — OPA's own built-in health endpoint |
| `jwks` | Verifies the JWKS cache holds at least one signing key |

```bash
curl http://localhost:9090/readyz
# all healthy:   {"jwks":{"status":"ok"},"opa":{"status":"ok"}}
# OPA is down:   {"jwks":{"status":"ok"},"opa":{"status":"error","error":"connection refused"}}
```

### `/metrics` — Prometheus

Exposes metrics in the OpenMetrics format. Scrape with any Prometheus-compatible collector.

```bash
curl -s http://localhost:9090/metrics | grep s3sentinel
```

| Metric | Type | Labels | Description |
|---|---|---|---|
| `s3sentinel_http_requests_total` | counter | `action`, `status` | All completed requests by S3 action and HTTP status code |
| `s3sentinel_http_request_duration_seconds` | histogram | `action` | End-to-end request latency |
| `s3sentinel_jwt_validations_total` | counter | `result` (`success`\|`error`) | JWT validation outcomes |
| `s3sentinel_opa_evaluations_total` | counter | `result` (`allow`\|`deny`\|`error`) | OPA policy decision outcomes |
| `s3sentinel_opa_evaluation_duration_seconds` | histogram | — | Time spent waiting for OPA |
| `s3sentinel_backend_requests_total` | counter | `status` | HTTP status codes returned by the backend S3 service |

Go runtime and process metrics (`go_*`, `process_*`) are included automatically.

### Kubernetes probe configuration

```yaml
livenessProbe:
  httpGet:
    path: /healthz
    port: 9090
  initialDelaySeconds: 5
  periodSeconds: 10

readinessProbe:
  httpGet:
    path: /readyz
    port: 9090
  initialDelaySeconds: 5
  periodSeconds: 10
  failureThreshold: 3
```

---

## 7  Local development with a mock IdP


If you do not have an IdP available locally, you can use [Dex](https://dexidp.io/) or generate a self-signed JWT for testing.

### Quick JWT with a local Keycloak

```bash
docker run -d --name keycloak -p 8080:8080 \
  -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:latest start-dev
```

1. Open `http://localhost:8080`, log in as `admin/admin`.
2. Create a realm (e.g. `dev`).
3. Create a client `s3sentinel` with **Direct Access Grants** enabled.
4. Create a user, set a password.
5. Add a mapper: **User Attribute → groups** → claim name `groups`, multivalued.

```bash
# Get a token
TOKEN=$(curl -s -X POST \
  http://localhost:8080/realms/dev/protocol/openid-connect/token \
  -d 'grant_type=password&client_id=s3sentinel&username=alice&password=alice' \
  | jq -r .access_token)

# Set env vars to point to Keycloak
export JWKS_ENDPOINT=http://localhost:8080/realms/dev/protocol/openid-connect/certs
export JWT_ISSUER=http://localhost:8080/realms/dev
```

### All three services running locally

```
Terminal 1 — OPA:    opa run --server --addr :8181 policy/
Terminal 2 — Proxy:  set -a && source .env && set +a && ./s3sentinel
Terminal 3 — Test:   curl -s http://localhost:8080/my-bucket -H "Authorization: Bearer $TOKEN"
```

---

## 8  Project structure

```
.
├── cmd/
│   └── s3sentinel/
│       └── main.go              # Entry point, signal handling, server wiring
├── internal/
│   ├── auth/
│   │   └── jwt.go               # OIDC JWT validation with JWKS caching
│   ├── config/
│   │   └── config.go            # Environment variable loading
│   ├── observability/
│   │   ├── health.go            # /healthz and /readyz handlers
│   │   └── metrics.go           # Prometheus metric definitions
│   ├── opa/
│   │   └── client.go            # OPA REST API client
│   ├── proxy/
│   │   └── handler.go           # Main pipeline: auth → OPA → re-sign → stream
│   ├── s3/
│   │   └── parser.go            # S3 action/bucket/key parser
│   └── sts/
│       ├── handler.go           # AssumeRoleWithWebIdentity HTTP handler
│       └── token.go             # Stateless credential issuance and SessionToken validation
├── policy/
│   └── s3.rego                  # Your OPA policy (not committed — add your own)
├── .env.example                 # Environment variable template
├── go.mod
└── go.sum
```

---

## 9  How it works

### Request flow

**Flow A — Direct JWT**

```
1. Client sends an S3-shaped HTTP request with an OIDC JWT in
   Authorization: Bearer <token>   or   X-Auth-Token: <token>

2. Proxy validates the JWT signature and claims against the IdP's JWKS.
   Expired / invalid tokens → 401.

3. Proxy parses the HTTP method + path + query to determine the S3 action
   (e.g. PUT /bucket/key → PutObject).

4. Proxy POSTs to OPA:
   { "input": { "principal", "email", "groups", "action", "bucket", "key" } }
   OPA returns { "result": true|false }.
   OPA deny → 403.  OPA error → 500 (fail-closed).

5. Proxy strips the client's auth headers and re-signs the request with the
   OVH service-account credentials using SigV4. The body hash is set to
   "UNSIGNED-PAYLOAD" — a standard SigV4 option that avoids buffering the
   entire request body for SHA-256 hashing, which matters for large uploads.

6. Proxy forwards to OVH Object Storage and streams the response back.
```

**Flow B — STS credential vending**

```
[Credential exchange — happens once per TTL]

1. Client POSTs to the STS server (:8090):
   Action=AssumeRoleWithWebIdentity
   WebIdentityToken=<OIDC JWT>

2. STS validates the JWT against the IdP's JWKS (same validator as the proxy).

3. STS issues three values:
   - AccessKeyID:     random, AWS-style identifier (ASIA...)
   - SecretAccessKey: random, used by the SDK for SigV4 signing
   - SessionToken:    HMAC-signed JWT containing { sub, email, groups, exp }
                      — stateless; no database or shared state required

[Every subsequent S3 request]

4. Client signs the request with AccessKeyID + SecretAccessKey (standard SigV4)
   and attaches the SessionToken in the X-Amz-Security-Token header.

5. Proxy detects the AWS4-HMAC-SHA256 Authorization header and reads the
   SessionToken from X-Amz-Security-Token.

6. Proxy validates the SessionToken's HMAC signature and expiry.
   The principal, email, and groups are extracted directly from the token.
   No JWKS lookup or IdP call is needed per-request.

7. Steps 3–6 of Flow A apply (OPA check → re-sign → forward).
```

The SessionToken is a signed JWT, not an opaque token — the proxy verifies it locally using the shared `STS_TOKEN_SECRET`. There is no token store, no revocation list, and no database. Access is revoked when the token expires (configurable via `STS_TOKEN_TTL`).

---

## 10  Supported S3 operations

| Category | Operations |
|---|---|
| Service | `ListBuckets` |
| Bucket | `HeadBucket`, `CreateBucket`, `DeleteBucket`, `ListObjects`, `ListObjectsV2`, `GetBucketAcl`, `PutBucketAcl`, `GetBucketLocation`, `GetBucketVersioning`, `PutBucketVersioning`, `GetBucketCors`, `PutBucketCors`, `DeleteBucketCors`, `ListMultipartUploads`, `DeleteObjects` |
| Object | `GetObject`, `HeadObject`, `PutObject`, `DeleteObject`, `CopyObject`, `GetObjectAcl`, `PutObjectAcl`, `GetObjectTagging`, `PutObjectTagging`, `DeleteObjectTagging` |
| Multipart | `CreateMultipartUpload`, `UploadPart`, `CompleteMultipartUpload`, `AbortMultipartUpload`, `ListParts` |

Requests with an action pattern that does not match any of the above are classified as `Unknown` and forwarded. Write an explicit OPA rule to allow or deny them.

---

## 11  Not supported

### Presigned URLs

Presigned URLs embed credentials and an expiry directly in a query string, bypassing the `Authorization` header entirely. The proxy has no way to extract or validate an OIDC identity from a presigned request, so they are not supported. All clients must present a JWT.

### Client-side AWS signature validation

The proxy does not verify the AWS SigV4 signature that S3 SDKs attach to requests. In Flow A, the client's identity comes from the OIDC JWT only — the fake AWS credentials configured in the SDK are never checked. In Flow B, the identity comes from the SessionToken JWT; the SigV4 signature is still not validated. This is intentional: the JWT (OIDC or session token) is the trust boundary, not the AWS signature.

### Unimplemented S3 operations

The following S3 API families are not in the action map. Requests that match them are classified as `Unknown` and forwarded to the backend without a named action — your OPA policy must handle `Unknown` explicitly if you want to block them.

| Family | Example operations |
|---|---|
| Object Lock / WORM | `GetObjectLegalHold`, `PutObjectLegalHold`, `GetObjectRetention`, `PutObjectRetention` |
| Bucket lifecycle | `GetBucketLifecycle`, `PutBucketLifecycle`, `DeleteBucketLifecycle` |
| Bucket replication | `GetBucketReplication`, `PutBucketReplication`, `DeleteBucketReplication` |
| Bucket notifications | `GetBucketNotificationConfiguration`, `PutBucketNotificationConfiguration` |
| Bucket policy | `GetBucketPolicy`, `PutBucketPolicy`, `DeleteBucketPolicy` |
| Bucket encryption | `GetBucketEncryption`, `PutBucketEncryption`, `DeleteBucketEncryption` |
| Static website hosting | `GetBucketWebsite`, `PutBucketWebsite`, `DeleteBucketWebsite` |
| S3 Select | `SelectObjectContent` |

Note: several of these (e.g. bucket policy, object lock) are also not supported by OVH Object Storage itself.

### Multiple backends / per-bucket routing

A single proxy instance routes all requests to one backend endpoint. There is no support for routing different buckets to different OVH regions or different providers.

### Automatic TLS certificate management (ACME)

TLS is configured via static certificate files. There is no built-in Let's Encrypt / ACME support. Use an external tool (Certbot, cert-manager) to obtain and renew certificates, and point `TLS_CERT_FILE` / `TLS_KEY_FILE` at the result.
