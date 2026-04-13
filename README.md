# S3 Fine-Grained Access Proxy

An S3-compatible reverse proxy that adds identity-aware, policy-driven access control on top of EU cloud object storage (OVHcloud, Scaleway, Exoscale, Hetzner, …).

EU cloud providers issue bucket-level service-account credentials only — there is no IAM, no STS, no resource-level policies. This proxy sits in front of your bucket, owns the service-account key, and gates every S3 operation through [OPA](https://www.openpolicyagent.org/) using the caller's OIDC identity.

```
Client (S3 SDK / CLI)
  │  Authorization: Bearer <OIDC JWT>
  ▼
S3 Proxy  :8080
  ├─ Validate JWT against your IdP's JWKS
  ├─ Parse S3 action (GetObject, PutObject, …)
  ├─ POST { principal, groups, action, bucket, key } → OPA
  ├─ Allowed → re-sign with OVH service-account credentials
  └─ Forward to OVH Object Storage, stream response back
```

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
git clone https://github.com/dataminded/s3-fine-grained-access.git
cd s3-fine-grained-access
go build -o s3proxy ./cmd/s3proxy
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
JWT_AUDIENCE=s3-proxy          # comma-separated if multiple; leave blank to skip
```

### 3c  Start the proxy

```bash
set -a && source .env && set +a
./s3proxy
# {"time":"...","level":"INFO","msg":"s3 proxy starting","addr":":8080","backend":"https://s3.gra.io.cloud.ovh.net"}
```

---

## 4  Call the proxy

### Using curl (Bearer token)

```bash
# Obtain a token from your IdP first:
TOKEN=$(curl -s -X POST https://your-idp.example.com/token \
  -d 'grant_type=password&client_id=s3-proxy&username=alice&password=...' \
  | jq -r .access_token)

# List objects
curl -s http://localhost:8080/my-bucket \
  -H "Authorization: Bearer $TOKEN" | cat

# Download an object
curl -s http://localhost:8080/my-bucket/datasets/report.csv \
  -H "Authorization: Bearer $TOKEN" -o report.csv

# Upload an object
curl -s -X PUT http://localhost:8080/my-bucket/raw/upload.csv \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: text/csv" \
  --data-binary @upload.csv
```

### Using the AWS CLI (S3 SDK-style with fake credentials)

The AWS CLI signs requests with its configured credentials. The proxy ignores that signature and instead reads the OIDC token from the `X-Auth-Token` header.

```bash
aws configure --profile s3proxy
# AWS Access Key ID:     anything   (e.g. PROXY)
# AWS Secret Access Key: anything   (e.g. PROXY)
# Default region name:  gra
# Default output format: json

# Pass the real JWT via the custom header
TOKEN=$(...)   # obtain from your IdP

aws s3 ls s3://my-bucket/ \
  --profile s3proxy \
  --endpoint-url http://localhost:8080 \
  --no-sign-request=false \
  --request-payer=requester \  # ignored by proxy
  -- $(: placeholder)          # see note below

# Simpler approach: use an AWS_DEFAULT_REGION + custom header via the SDK
AWS_DEFAULT_REGION=gra \
aws s3api get-object \
  --profile s3proxy \
  --endpoint-url http://localhost:8080 \
  --bucket my-bucket \
  --key datasets/report.csv \
  --request-payer requester \
  outfile.csv \
  --cli-override-endpoint-url http://localhost:8080 \
  # pass token: add --no-sign-request and use a wrapper script, or use Python SDK below
```

> **Tip — easiest SDK integration:** Use the Python `boto3` client, which lets you inject custom headers per-request via an event hook. See [the boto3 events documentation](https://boto3.amazonaws.com/v1/documentation/api/latest/guide/events.html).

```python
import boto3
from botocore.auth import SigV4Auth
from botocore import UNSIGNED
from botocore.config import Config

TOKEN = "..."   # your OIDC JWT

s3 = boto3.client(
    "s3",
    endpoint_url="http://localhost:8080",
    aws_access_key_id="PROXY",          # fake – ignored by proxy
    aws_secret_access_key="PROXY",      # fake – ignored by proxy
    region_name="gra",
    config=Config(signature_version=UNSIGNED),
)

# Inject the JWT on every request
def add_auth_header(request, **kwargs):
    request.headers["Authorization"] = f"Bearer {TOKEN}"

s3.meta.events.register("before-send.s3.*", add_auth_header)

# Use normally
response = s3.list_objects_v2(Bucket="my-bucket", Prefix="datasets/")
for obj in response.get("Contents", []):
    print(obj["Key"])
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
curl -s http://localhost:9090/metrics | grep s3proxy
```

| Metric | Type | Labels | Description |
|---|---|---|---|
| `s3proxy_http_requests_total` | counter | `action`, `status` | All completed requests by S3 action and HTTP status code |
| `s3proxy_http_request_duration_seconds` | histogram | `action` | End-to-end request latency |
| `s3proxy_jwt_validations_total` | counter | `result` (`success`\|`error`) | JWT validation outcomes |
| `s3proxy_opa_evaluations_total` | counter | `result` (`allow`\|`deny`\|`error`) | OPA policy decision outcomes |
| `s3proxy_opa_evaluation_duration_seconds` | histogram | — | Time spent waiting for OPA |
| `s3proxy_backend_requests_total` | counter | `status` | HTTP status codes returned by the backend S3 service |

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
3. Create a client `s3-proxy` with **Direct Access Grants** enabled.
4. Create a user, set a password.
5. Add a mapper: **User Attribute → groups** → claim name `groups`, multivalued.

```bash
# Get a token
TOKEN=$(curl -s -X POST \
  http://localhost:8080/realms/dev/protocol/openid-connect/token \
  -d 'grant_type=password&client_id=s3-proxy&username=alice&password=alice' \
  | jq -r .access_token)

# Set env vars to point to Keycloak
export JWKS_ENDPOINT=http://localhost:8080/realms/dev/protocol/openid-connect/certs
export JWT_ISSUER=http://localhost:8080/realms/dev
```

### All three services running locally

```
Terminal 1 — OPA:    opa run --server --addr :8181 policy/
Terminal 2 — Proxy:  set -a && source .env && set +a && ./s3proxy
Terminal 3 — Test:   curl -s http://localhost:8080/my-bucket -H "Authorization: Bearer $TOKEN"
```

---

## 8  Project structure

```
.
├── cmd/
│   └── s3proxy/
│       └── main.go              # Entry point, signal handling
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
│   └── s3/
│       └── parser.go            # S3 action/bucket/key parser
├── policy/
│   └── s3.rego                  # Your OPA policy (not committed — add your own)
├── .env.example                 # Environment variable template
├── go.mod
└── go.sum
```

---

## 9  How it works

### Request flow

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
   OVH service-account credentials using SigV4. The body hash in the signature
   is set to the literal string "UNSIGNED-PAYLOAD" — a standard SigV4 option
   that tells the server not to verify the body hash. This avoids reading the
   entire request body into memory before forwarding, which matters for large
   PutObject uploads. OVH Object Storage (and all Ceph-based providers) accept
   unsigned payloads.

6. Proxy forwards to OVH Object Storage and streams the response back.
```

### Token delivery for S3 SDKs

S3 SDKs always send an `Authorization: AWS4-HMAC-SHA256 ...` header. To use the proxy transparently from any SDK:

- Configure the SDK with **any** fake access key and secret (the proxy ignores the AWS signature).
- Pass the OIDC JWT in the custom `X-Auth-Token` header (the proxy reads it from there).
- Point the SDK's `endpoint_url` at the proxy.

The `Authorization: Bearer` path is the simpler alternative for direct HTTP callers (curl, httpx, etc.).

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

The proxy does not verify the AWS SigV4 signature that S3 SDKs attach to requests. It reads the client's identity from the OIDC JWT only. The fake AWS credentials configured in the SDK are never checked — any key/secret pair is accepted. This is intentional: the JWT is the trust boundary, not the AWS signature.

### STS / temporary credential vending

There is no STS endpoint. The proxy does not issue short-lived AWS credentials to callers. If your tooling requires `AssumeRoleWithWebIdentity` or similar, you need a separate credential-vending service in front of the proxy.

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
