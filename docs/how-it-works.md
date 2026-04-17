# Request flow

## Flow A — Direct JWT

```
Client ──[Authorization: Bearer <OIDC JWT>]──► Proxy :8080
                                                 ├─ Validate JWT (JWKS)
                                                 ├─ Check OPA
                                                 ├─ Re-sign → OVH S3
                                                 └─ Stream response back
```

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

## Flow B — STS credential vending
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

The SessionToken is a signed JWT, not an opaque token. 
The proxy verifies it locally using the shared `STS_TOKEN_SECRET`. 
There is no token store, no revocation list, and no database. 
Access is revoked when the token expires (configurable via `STS_TOKEN_TTL`).