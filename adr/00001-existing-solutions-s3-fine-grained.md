# Existing Options: Fine-Grained Access Control for S3-Compatible Storage

**Research date:** 2026-04-13

---

## Context

This document summarizes existing open-source projects and prior art for adding fine-grained access control (OIDC authentication + policy-driven authorization) on top of S3-compatible object storage — specifically targeting EU cloud providers that lack native IAM, STS, or attribute-based access control.

Requirements driving this research:
- OIDC-based authentication (no static access keys distributed to clients)
- Policy-driven authorization per S3 operation and object path
- OPA as the policy engine (ideally)
- Full S3 API compatibility: all workloads, not just tabular data
- Presigned URL support
- Works as a proxy in front of any S3-compatible backend

---

## Projects Found

### 1. fakes3pp — VITObelgium

**Repository:** https://github.com/VITObelgium/fakes3pp  
**Author:** VITO (Flemish Institute for Technological Research), Belgium  
**Language:** Go

A proxy that enriches S3-compatible APIs with OIDC authentication, presigned URLs, and fine-grained authorization. Built specifically to close the gap with AWS S3's IAM/STS capabilities on EU cloud providers — the same problem space.

**Authentication flow:**
1. Client obtains OIDC token from IdP
2. Client calls `AssumeRoleWithWebIdentity` against fakes3pp's STS endpoint → receives temporary AWS-compatible credentials
3. Client uses those credentials for standard S3 calls → fakes3pp authorizes and proxies to the underlying EU cloud S3

**S3 operations covered:**
- GetObject, HeadObject, HeadBucket, ListObjectsV2, ListBuckets
- PutObject, DeleteObject
- CreateMultipartUpload, UploadPart, CompleteMultipartUpload, AbortMultipartUpload
- Presigned URLs (solved — the hardest part)

**Policy engine:** Custom IAM-style YAML policies in `etc/policies`. **Not OPA.** Policies are mapped from the OIDC subject claim.

**Production readiness:** Helm charts included, documentation covers secret management and production configuration.

**Gap:** No OPA integration. The policy system is custom and not interoperable with a centralized OPA setup.

**Assessment:** The closest existing solution. The hard engineering problems — STS flow, presigned URLs, full S3 API coverage — are already solved. If OPA is required, fakes3pp is a better base to fork and extend than building from scratch.

---

### 2. oxyno-zeta/s3-proxy

**Repository:** https://github.com/oxyno-zeta/s3-proxy  
**Language:** Go

An S3 reverse proxy with OIDC authentication and native OPA integration. Designed for controlled access to S3 buckets via a web interface.

**Authentication:** OpenID Connect with multiple provider support, configurable per bucket and path.

**OPA integration:** After OIDC login, sends a structured JSON payload to an OPA REST endpoint:
```json
{
  "user": { "preferred_username": "...", "groups": [...], "email": "..." },
  "request": { "method": "GET", "path": "/bucket/prefix/file.parquet", "headers": {...} },
  "tags": {}
}
```
OPA returns `{"result": true}` to allow or `false` to deny.

**S3 operations covered:** GET, PUT, DELETE only. No multipart upload, no presigned URLs.

**Gap:** Incomplete S3 API — Spark, DuckDB, and boto3 multipart writes would fail. Not suitable as a full S3-API-compatible proxy for all workloads.

**Assessment:** The OPA integration is well-designed and reusable as a reference. The missing S3 coverage makes it unsuitable as-is, but the OPA wiring pattern is worth adopting.

---

### 3. Dataminded — Locking down your data: fine-grained data access on EU Clouds

**Article:** https://www.dataminded.com/resources/locking-down-your-data-fine-grained-data-access-on-eu-clouds  
**Author:** Niels Claeys, Dataminded

Documents the same problem and proposes a solution for the **tabular data** (Iceberg) use case:

- **Zitadel** for OIDC authentication (service users with client credentials flow)
- **Lakekeeper** with remote-signing: applications request a signed S3 URL from Lakekeeper, which authorizes the request and signs it with the service account — the application never sees the credentials
- **OPA-bridge** for controlling SQL query access via Trino

The article explicitly concludes: *"non-tabular data types remain unaddressed."* This gap is what motivates the current investigation.

---

## Gap Analysis

| | OIDC | OPA | Full S3 API | Presigned URLs | Non-tabular workloads |
|---|---|---|---|---|---|
| fakes3pp | Yes (STS) | No (custom engine) | Yes | Yes | Yes |
| oxyno-zeta/s3-proxy | Yes | Yes | No (GET/PUT/DELETE) | No | Partial |
| Lakekeeper (remote-signing) | Yes | Via bridge | Iceberg only | No | No |
| **Required** | Yes | Yes | Yes | Yes | Yes |

No existing open-source project covers all requirements. The two closest are:
- **fakes3pp**: missing OPA, but solves everything else
- **oxyno-zeta/s3-proxy**: has OPA, but missing multipart and presigned URLs

---

## Conclusions

1. **You are not the first.** VITO (Belgium) built fakes3pp to solve the identical EU cloud problem. The hard parts — STS credential vending, presigned URLs, full multipart S3 API — are already implemented.

2. **fakes3pp is the recommended starting point** if a custom or extended solution is pursued. Forking it to replace the custom policy engine with OPA is a bounded contribution (~days of work) compared to building from scratch (~weeks).

3. **oxyno-zeta/s3-proxy's OPA wiring** is a useful reference for the policy evaluation pattern, even if the project itself is insufficient for full S3 workloads.

4. **Contacting VITO directly** may be worthwhile — they are a Belgian research institute working in the same EU cloud context and may have plans for or interest in OPA integration.
