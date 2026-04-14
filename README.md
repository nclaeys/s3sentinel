# S3 Sentinel

An S3-compatible reverse proxy that adds identity-aware, policy-driven access control on top of EU cloud object storage (OVHcloud, Scaleway, Exoscale, Hetzner, …).
EU cloud providers issue bucket-level service-account credentials mainly and have limited/no support for STS, resource-level policies. 
This proxy sits in front of your bucket, owns the service-account key, and authorizes every S3 operation with [OPA](https://www.openpolicyagent.org/) based on the caller's OIDC identity.

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

Flow B is compatible with every AWS SDK like: boto3, AWS CLI, Spark, DuckDB,...
All of them support `AssumeRoleWithWebIdentity` natively.

## Prerequisites

| Tool                    | Minimum version | Install                                                                             |
|-------------------------|-----------------|-------------------------------------------------------------------------------------|
| Go                      | 1.22            | <https://go.dev/dl/>                                                                |
| OPA                     | 0.65            | `brew install opa` or [download](https://github.com/open-policy-agent/opa/releases) |
| An S3 compatible bucket | —               | OVH Control Panel                                                                   |
| An OIDC-capable IdP     | —               | Keycloak, Dex, Auth0, Google, …                                                     |

## Getting started

Take a look at the `examples/basic` directory for a quickstart using the provided docker-compose file.

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
│   ├── config/
│   ├── observability/
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

## Configuring s3 sentinel to fit your needs

### Create your object Storage credentials

#### Find your endpoint and region

In the OVH Control Panel, go to **Public Cloud → Object Storage → your container** and note:

- **Region** — shown in the container list (e.g. `GRA`, `SBG`, `WAW`). The proxy uses the lowercase form: `gra`, `sbg`, `waw`.
- **Endpoint** — the S3-compatible URL for that region:

#### Create S3 credentials

The proxy uses a single service-account key pair with full bucket access. Clients never see it.
When using OVH, you can get the credentials as follows:

1. In the OVH Control Panel open **Public Cloud → Users & Roles → Users**.
2. Create a user (or use an existing one) with the **ObjectStore operator** role.
3. Click the user → **S3 credentials** tab → **Generate credentials**.
4. Save the **Access key** and **Secret key** — they are shown only once.


### Create your OPA policies

OPA runs as a separate component and contains the policies for deciding whether a request is allowed or not. 
S3sentinel calls OPA for every request before forwarding the request to the S3 compatible backend.

#### Policy input format

The proxy provides the following context to OPA:
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

#### Create a policy

S3sentinel does not include any built-in policies so you must write your own to get started.
Take a look at the [OPA documentation](https://www.openpolicyagent.org/docs/latest/policy-language/) and the example policy in `examples/basic/policy/reader-admin-policy.rego.

#### Test your policy

Add your policies in `examples/basic/policy/` directory and run `docker-compose up -d` from the `examples/basic` directory.
OPA is now listening on `http://localhost:8181`.

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


## How it works

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