# S3 Sentinel

[![CI](https://github.com/nclaeys/s3sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/nclaeys/s3sentinel/actions/workflows/ci.yml)
[![Go 1.25](https://img.shields.io/badge/go-1.25-00ADD8?logo=go)](https://go.dev/dl/)
[![Go Report Card](https://goreportcard.com/badge/github.com/nclaeys/s3sentinel)](https://goreportcard.com/report/github.com/nclaeys/s3sentinel)
[![golangci-lint](https://img.shields.io/badge/golangci--lint-enabled-success)](https://golangci-lint.run/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

An S3-compatible reverse proxy that adds **identity-aware, policy-driven access control** on top of any S3-compatible object storage (OVHcloud, Scaleway, Exoscale, Hetzner, MinIO, …).

EU cloud providers issue bucket-level service-account credentials and have limited or no support for STS or resource-level policies. S3 Sentinel sits in front of your bucket, owns the service-account key, and authorises every S3 operation against [OPA](https://www.openpolicyagent.org/) using the caller's OIDC identity — without requiring any changes to existing S3 client code.

```
Your clients                S3 Sentinel                  Object storage
─────────────               ─────────────                ──────────────
boto3 / AWS CLI ──► :8080  validate JWT ──► OPA :8181   
DuckDB          ──► :8080  authorise    ──► re-sign  ──► MinIO / OVH / Scaleway
Spark           ──► :8090  issue creds                   
                   (STS)
```

Two authentication flows are supported:

| Flow                           | How it works                                                                                                                            | Best for                                                          |
|--------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------|
| **A — Direct JWT**             | Client sends an OIDC token on every request (`Authorization: Bearer` or `X-Auth-Token`).                                                | Scripts, curl, custom clients                                     |
| **B — STS credential vending** | Client exchanges an OIDC token for short-lived AWS credentials via `AssumeRoleWithWebIdentity`. Subsequent requests use standard SigV4. | boto3, AWS CLI, Spark, DuckDB — any tool that speaks AWS natively |

---

## Contents

- [Quick start](#quick-start)
- [How it works](#how-it-works)
- [Configuration reference](#configuration-reference)
- [Supported S3 operations](#supported-s3-operations)
- [Project structure](#project-structure)
- [Building and running](#building-and-running)
- [Not supported](#not-supported)
- [Contributing](#contributing)

---

## Quick start

The fastest way to try S3 Sentinel is with the bundled Docker Compose example. It wires together MinIO, Keycloak, OPA, and S3 Sentinel in one command.

```bash
# Clone and start the stack (from the project root)
git clone https://github.com/nclaeys/s3sentinel.git
cd s3sentinel
docker compose -f examples/basic/docker-compose.yml up --build
```

Keycloak takes ~30–60 seconds on first start. Once all services are healthy:

```bash
# Confirm the proxy is ready
curl -s http://localhost:9090/readyz | jq .
# {"jwks":{"status":"ok"},"opa":{"status":"ok"}}
```

Then follow the [walkthrough in examples/basic/README.md](examples/basic/README.md) to see uploads, downloads, access-denied responses, STS credential vending, and DuckDB queries — all through the proxy.

---

## How it works

See [docs/how-it-works.md](docs/how-it-works.md) for a step-by-step description of both request flows with sequence diagrams.

**Flow A — Direct JWT**

```
1. Client  →  Proxy :8080    Authorization: Bearer <OIDC JWT>
2. Proxy   →  IdP JWKS       validate signature + claims
3. Proxy   →  OPA :8181      POST { principal, email, groups, action, bucket, key }
4. Proxy   →  Backend        re-sign with service-account SigV4, stream response
```

**Flow B — STS**

```
1. Client  →  STS :8090      POST Action=AssumeRoleWithWebIdentity&WebIdentityToken=<JWT>
2. STS     →  IdP JWKS       validate JWT
3. STS     →  Client         { AccessKeyID, SecretAccessKey, SessionToken (HMAC JWT) }

   (then, on every S3 request)

4. Client  →  Proxy :8080    AWS SigV4 + X-Amz-Security-Token: <SessionToken>
5. Proxy               →     validate SessionToken locally (no IdP call), check OPA, re-sign, forward
```

The SessionToken is a stateless HMAC-signed JWT. No database or shared state is required. Access expires when the token TTL elapses.

---

## Configuration reference

All configuration is via environment variables. A minimal `.env` file:

```dotenv
BACKEND_ENDPOINT=https://s3.gra.io.cloud.ovh.net
BACKEND_ACCESS_KEY=your-service-account-key
BACKEND_SECRET_KEY=your-service-account-secret
OPA_ENDPOINT=http://opa:8181/v1/data/s3/allow
JWKS_ENDPOINT=https://your-idp.example.com/.well-known/jwks.json
```

| Environment variable | Required | Default     | Description |
|----------------------|----------|-------------|-------------|
| `LISTEN_ADDR`        | no       | `:8080`     | Address the proxy listens on |
| `BACKEND_ENDPOINT`   | **yes**  | —           | Full URL of your S3-compatible backend (e.g. `https://s3.gra.io.cloud.ovh.net`) |
| `BACKEND_REGION`     | no       | `us-east-1` | S3 region used in the SigV4 re-signature |
| `BACKEND_ACCESS_KEY` | **yes**  | —           | Service-account access key for the backend |
| `BACKEND_SECRET_KEY` | **yes**  | —           | Service-account secret key for the backend |
| `PROXY_HOST`         | no       | —           | Proxy's own hostname, required for virtual-hosted-style requests (e.g. `s3.internal.example.com`) |
| `ADMIN_ADDR`         | no       | `:9090`     | Admin server address — exposes `/healthz`, `/readyz`, `/metrics` |
| `TLS_CERT_FILE`      | no       | —           | PEM certificate (or full chain). Set both TLS vars to enable HTTPS. |
| `TLS_KEY_FILE`       | no       | —           | PEM private key |
| `OPA_ENDPOINT`       | **yes**  | —           | Full URL to the OPA decision endpoint, e.g. `http://opa:8181/v1/data/s3/allow` |
| `JWKS_ENDPOINT`      | **yes**  | —           | JWKS URI from your IdP |
| `JWT_ISSUER`         | no       | —           | Expected `iss` claim; omit to skip issuer validation |
| `JWT_AUDIENCE`       | no       | —           | Comma-separated expected `aud` claims; omit to skip |
| `STS_TOKEN_SECRET`   | no       | —           | HMAC key for STS credentials. Enables the STS server and session-token auth. Generate with `openssl rand -hex 32`. |
| `STS_LISTEN_ADDR`    | no       | `:8090`     | STS server address (only when `STS_TOKEN_SECRET` is set) |
| `STS_TOKEN_TTL`      | no       | `1h`        | Credential lifetime. Go duration syntax: `30m`, `2h`, `24h`. |

### Enabling TLS

Set both `TLS_CERT_FILE` and `TLS_KEY_FILE`. The proxy re-reads the certificate on each new TLS handshake, so rotation does not require a restart.

For local testing:

```bash
openssl req -x509 -newkey rsa:4096 -sha256 -days 365 -nodes \
  -keyout key.pem -out cert.pem \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
```

For production, use [Certbot](https://certbot.eff.org/) or [cert-manager](https://cert-manager.io/).

### Writing OPA policies

Policies receive the following `input` document on every S3 request:

```json
{
  "principal": "alice",
  "email": "alice@example.com",
  "groups": ["engineers", "readers"],
  "action": "GetObject",
  "bucket": "my-bucket",
  "key": "path/to/object.parquet"
}
```

A minimal Rego policy:

```rego
package s3

import rego.v1

default allow := false

# Admins can do anything.
allow if { input.groups[_] == "admin" }

# Readers can read.
allow if {
    input.groups[_] == "reader"
    input.action in {"GetObject", "HeadObject", "ListObjects", "ListObjectsV2"}
}
```

See [docs/use-it-your-setup.md](docs/use-it-your-setup.md) for a complete setup guide.

---

## Supported S3 operations

| Category  | Operations |
|-----------|------------|
| Service   | `ListBuckets` |
| Bucket    | `HeadBucket`, `CreateBucket`, `DeleteBucket`, `ListObjects`, `ListObjectsV2`, `GetBucketAcl`, `PutBucketAcl`, `GetBucketLocation`, `GetBucketVersioning`, `PutBucketVersioning`, `GetBucketCors`, `PutBucketCors`, `DeleteBucketCors`, `ListMultipartUploads`, `DeleteObjects` |
| Object    | `GetObject`, `HeadObject`, `PutObject`, `DeleteObject`, `CopyObject`, `GetObjectAcl`, `PutObjectAcl`, `GetObjectTagging`, `PutObjectTagging`, `DeleteObjectTagging` |
| Multipart | `CreateMultipartUpload`, `UploadPart`, `CompleteMultipartUpload`, `AbortMultipartUpload`, `ListParts` |

Requests that do not match any of the above are classified as `Unknown` and forwarded as-is. Write an explicit OPA rule to allow or deny `Unknown` operations.

---

## Project structure

```
.
├── cmd/s3sentinel/
│   └── main.go                  # Entry point — signal handling, server wiring
├── internal/
│   ├── proxy/                   # Core pipeline: auth → OPA → re-sign → stream
│   ├── s3/                      # S3 action/bucket/key parser
│   └── sts/                     # STS credential vending server
├── examples/basic/
│   ├── docker-compose.yml       # Full local stack (MinIO + Keycloak + OPA + S3 Sentinel)
│   ├── demo.py                  # STS flow with boto3
│   └── parquet_demo.py          # Write Parquet to MinIO, query with DuckDB
├── policy/
│   └── s3.rego                  # Example OPA policy
├── docs/
│   ├── how-it-works.md          # Detailed request flow
│   └── use-it-your-setup.md     # Step-by-step production setup guide
```

---

## Building and running

**Prerequisites:** Go 1.25+, OPA 1.10+, an S3-compatible bucket, an OIDC-capable IdP.

### From source

```bash
make build
./s3sentinel
```

### Docker

```bash
docker build -t s3sentinel .
docker run --rm --env-file .env \
  -p 8080:8080 -p 8090:8090 -p 9090:9090 \
  s3sentinel
```

### Development

```bash
make test          # run all tests
make lint          # run golangci-lint
make check         # vet + tests + lint (same as CI)
make test-race     # tests with -race
make cover         # coverage report in browser
```

---

## Not supported

### Presigned URLs

Presigned URLs embed credentials in the query string, bypassing the `Authorization` header. The proxy cannot extract an OIDC identity from them. All clients must present a JWT.

### Client-side SigV4 signature validation

The proxy does not verify the AWS SigV4 signature that S3 SDKs attach to requests. Identity comes from the JWT or SessionToken only — the fake AWS credentials clients configure for SDK signing are never checked. This is intentional: the JWT is the trust boundary, not the AWS signature.

### Unimplemented S3 operations

The following API families are not in the action map. Requests matching them are classified as `Unknown` and forwarded without a named action.

| Family | Example operations |
|--------|--------------------|
| Object Lock / WORM | `GetObjectLegalHold`, `PutObjectLegalHold`, `GetObjectRetention`, `PutObjectRetention` |
| Bucket lifecycle | `GetBucketLifecycle`, `PutBucketLifecycle`, `DeleteBucketLifecycle` |
| Bucket replication | `GetBucketReplication`, `PutBucketReplication`, `DeleteBucketReplication` |
| Bucket notifications | `GetBucketNotificationConfiguration`, `PutBucketNotificationConfiguration` |
| Bucket policy | `GetBucketPolicy`, `PutBucketPolicy`, `DeleteBucketPolicy` |
| Bucket encryption | `GetBucketEncryption`, `PutBucketEncryption`, `DeleteBucketEncryption` |
| Static website hosting | `GetBucketWebsite`, `PutBucketWebsite`, `DeleteBucketWebsite` |
| S3 Select | `SelectObjectContent` |

### Multiple backends

A single instance routes all requests to one backend. Per-bucket or per-region routing is not supported.

### Automatic TLS (ACME)

TLS uses static certificate files. Use an external tool (Certbot, cert-manager) to manage certificates.

---

## Contributing

Contributions are welcome! Please:

1. Open an issue to discuss the change before sending a large PR.
2. Run `make check` (vet + tests + lint) locally before pushing — CI enforces the same gates.
3. Keep commits focused; one logical change per PR.

Bug reports, documentation improvements, and new example integrations are all appreciated.

## Maintainer

[Niels Claeys](https://github.com/nclaeys) — niels.claeys@gmail.com
