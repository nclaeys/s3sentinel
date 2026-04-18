# S3 Sentinel

An S3-compatible reverse proxy that adds identity-aware, policy-driven access control on top of EU cloud object storage (OVHcloud, Scaleway, Exoscale, Hetzner, …).
EU cloud providers issue bucket-level service-account credentials mainly and have limited/no support for STS, resource-level policies. 
This proxy sits in front of your bucket, owns the service-account key, and authorizes every S3 operation with [OPA](https://www.openpolicyagent.org/) based on the caller's OIDC identity.

Two authentication flows are supported:
- Direct JWT (clients present an OIDC token on every request, the proxy validates it and extracts identity claims)
- STS credential vending (clients exchange an OIDC token for short-lived AWS credentials, then use those credentials in subsequent requests)

Flow B is compatible with boto3, AWS CLI, Spark, DuckDB,... since all of them support `AssumeRoleWithWebIdentity` natively.

## Prerequisites

| Tool                    | Minimum version | Install                                                                             |
|-------------------------|-----------------|-------------------------------------------------------------------------------------|
| Go                      | 1.25            | <https://go.dev/dl/>                                                                |
| OPA                     | 1.10            | `brew install opa` or [download](https://github.com/open-policy-agent/opa/releases) |
| An S3 compatible bucket | —               | OVH, Minio (local development), Scaleway,...                                        |
| An OIDC-capable IdP     | —               | Keycloak, Zitadel, Auth0, Google                                                    |

## Getting started

Take a look at the [basic example](examples/basic/README.md) for a quickstart using the provided docker-compose file.

## Configuration reference

| Environment variable | Required | Default     | Description                                                                                                                                                    |
|----------------------|----------|-------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `LISTEN_ADDR`        | no       | `:8080`     | Address and port the proxy listens on                                                                                                                          |
| `BACKEND_ENDPOINT`   | **yes**  | —           | Full URL of the OVH S3 endpoint                                                                                                                                |
| `BACKEND_REGION`     | no       | `us-east-1` | S3 region sent in the SigV4 signature                                                                                                                          |
| `BACKEND_ACCESS_KEY` | **yes**  | —           | OVH service-account access key                                                                                                                                 |
| `BACKEND_SECRET_KEY` | **yes**  | —           | OVH service-account secret key                                                                                                                                 |
| `PROXY_HOST`         | no       | —           | Proxy's own hostname for virtual-hosted-style detection (e.g. `s3.internal.example.com`)                                                                       |
| `ADMIN_ADDR`         | no       | `:9090`     | Address for the admin server (`/healthz`, `/readyz`, `/metrics`)                                                                                               |
| `TLS_CERT_FILE`      | no       | —           | Path to PEM certificate file (or full chain). Both `TLS_CERT_FILE` and `TLS_KEY_FILE` must be set to enable HTTPS.                                             |
| `TLS_KEY_FILE`       | no       | —           | Path to PEM private key file.                                                                                                                                  |
| `OPA_ENDPOINT`       | **yes**  | —           | Full URL to the OPA rule, e.g. `http://opa:8181/v1/data/s3/allow`                                                                                              |
| `JWKS_ENDPOINT`      | **yes**  | —           | JWKS URI from your IdP                                                                                                                                         |
| `JWT_ISSUER`         | no       | —           | Expected `iss` claim; omit to skip issuer validation                                                                                                           |
| `JWT_AUDIENCE`       | no       | —           | Comma-separated expected `aud` claims; omit to skip                                                                                                            |
| `STS_TOKEN_SECRET`   | no       | —           | HMAC key for signing/validating SessionToken JWTs. When set, the STS server starts and the proxy accepts session tokens. Generate with `openssl rand -hex 32`. |
| `STS_LISTEN_ADDR`    | no       | `:8090`     | Address the STS server listens on (only used when `STS_TOKEN_SECRET` is set)                                                                                   |
| `STS_TOKEN_TTL`      | no       | `1h`        | Lifetime of issued credentials. Go duration syntax: `30m`, `2h`, `24h`.                                                                                        |

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

## Project structure

```
.
├── cmd/
│   └── s3sentinel/
│       └── main.go              # Entry point, signal handling, server wiring
├── internal/
│   ├── auth/                    # OIDC JWT validation with JWKS caching
│   ├── opa/                     # OPA REST API client
│   ├── proxy/                   # Main pipeline: auth → OPA → re-sign → stream
│   ├── s3/                      # S3 action/bucket/key parser to prepare OPA input
│   └── sts/                     # STS credential vending server
├── policy/
│   └── s3.rego                  # Your OPA policies
```

## Supported S3 operations

| Category  | Operations                                                                                                                                                                                                                                                                     |
|-----------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Service   | `ListBuckets`                                                                                                                                                                                                                                                                  |
| Bucket    | `HeadBucket`, `CreateBucket`, `DeleteBucket`, `ListObjects`, `ListObjectsV2`, `GetBucketAcl`, `PutBucketAcl`, `GetBucketLocation`, `GetBucketVersioning`, `PutBucketVersioning`, `GetBucketCors`, `PutBucketCors`, `DeleteBucketCors`, `ListMultipartUploads`, `DeleteObjects` |
| Object    | `GetObject`, `HeadObject`, `PutObject`, `DeleteObject`, `CopyObject`, `GetObjectAcl`, `PutObjectAcl`, `GetObjectTagging`, `PutObjectTagging`, `DeleteObjectTagging`                                                                                                            |
| Multipart | `CreateMultipartUpload`, `UploadPart`, `CompleteMultipartUpload`, `AbortMultipartUpload`, `ListParts`                                                                                                                                                                          |

Requests with an action pattern that does not match any of the above are classified as `Unknown` and forwarded. Write an explicit OPA rule to allow or deny them.


## Not supported

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

## Configuring s3 sentinel in your environment

Read the step-by-step guide in [docs/use-it-your-setup.md](docs/use-it-your-setup.md) to configure s3 sentinel with your OIDC provider, OPA policies, and an S3 compatible Object Storage bucket.

## How it works

Read the detailed request flow in [docs/how-it-works.md](docs/how-it-works.md).