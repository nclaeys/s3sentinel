# ADR: Fine-Grained Access Control for S3-Compatible Storage on EU Cloud Providers

**Status:** Proposed  
**Date:** 2026-04-13

---

## Context

EU cloud providers (OVHcloud, Scaleway, Exoscale, Hetzner, etc.) offer S3-compatible object storage but provide only coarse-grained access control — typically a single read/write or read-only key per bucket. There is no native support for identity federation, per-path policies, or attribute-based access control.

We need a mediation layer that:
- Authenticates clients via OIDC
- Enforces fine-grained, policy-driven access control on every S3 operation
- Supports all workload types: tabular data (Iceberg, Delta), ML artifacts, raw files, general object access
- Uses a single service account toward the underlying EU cloud S3 (the service account is never exposed to clients)

Evaluated and ruled out:
- **MinIO Gateway** — deprecated since 2022
- **Apache Ranger** — scoped to data warehouse/Hadoop workloads, does not cover general S3 access
- **Lakekeeper** — Iceberg catalog only, not general object storage access control

---

## Decision

We will use **LakeFS Community Edition** as the access control and mediation layer, with a fallback path to a **custom S3 proxy + OPA** if policy requirements exceed what LakeFS's built-in engine can express.

---

## Options Considered

### Option 1: LakeFS Community Edition

LakeFS sits in front of EU cloud S3 using a single service account, exposes an S3-compatible API to clients, and enforces its own IAM-style access control layer.

**Pros:**
- Works with all workloads — Spark, Trino, DuckDB, boto3, and any S3-compatible client
- OIDC authentication is built-in and production-ready
- Path-level fine-grained policies out of the box (prefix, repository, branch scoping)
- Versioning and branching are a genuine bonus for data engineering workflows
- Operational tooling included: UI, audit logs, hooks
- Time to first running system: days, not weeks
- Long-term maintenance is handled by upstream

**Cons:**
- The policy engine is **custom and proprietary** — it is modeled after AWS IAM syntax (JSON policies, action/resource ARN structure) but uses LakeFS-specific actions (`fs:ReadObject`, `fs:CreateBranch`, etc.) and is not based on any open standard (not OPA, Cedar, XACML, or OpenFGA). Policies are not portable to other systems.
- If your organization already manages authorization centrally in OPA, LakeFS CE policies become a second, isolated policy system — you cannot reuse existing Rego rules
- Complex ABAC rules (e.g., matching object tags to OIDC claims) are not expressible in the community edition
- OPA integration is available only in LakeFS Enterprise (paid)
- The Git-like model (repo/branch/path) is mandatory and changes the storage URL scheme for all clients
- Requires PostgreSQL as a metadata store
- Existing data must be migrated into LakeFS repositories

### Option 2: Custom S3 Proxy + OPA

A purpose-built HTTP proxy that speaks the S3 wire protocol, validates OIDC tokens, delegates every access decision to OPA, and re-signs allowed requests with service account credentials before forwarding to EU cloud S3.

```
Client (boto3, Spark, DuckDB)
  │  Authorization: Bearer <OIDC JWT>
  ▼
S3 Proxy
  ├─ Parse S3 request (method, bucket, key)
  ├─ Validate JWT via JWKS endpoint
  ├─ Build OPA input: { principal, action, resource, context }
  ├─ Evaluate OPA policy (embedded, <1ms, no network hop)
  ├─ Deny → 403 in S3 XML error format
  └─ Allow → re-sign with service account → forward → stream response
```

**Pros:**
- Full OPA expressiveness: ABAC, dynamic data from external sources, policy-as-code
- Transparent to clients — no URL scheme change, no branch model
- No versioning overhead
- No PostgreSQL dependency
- OPA integration itself is straightforward (~50 lines of Go using the embedded SDK)

**Cons:**
- Presigned URL support is complex: auth is baked into the URL, so OIDC token is not present. Options are: (a) disable presigned URLs, (b) issue proxy-signed tokens, or (c) vend short-lived scoped credentials — each adds significant scope
- Full S3 wire compatibility (multipart, Range requests, error XML format) requires careful implementation
- Realistic effort: 4–6 weeks to MVP, 8–10 weeks to production-ready
- Long-term maintenance burden: S3 API edge cases, client compatibility, EU cloud provider quirks

---

## Comparison

| | LakeFS CE | Custom Proxy + OPA |
|---|---|---|
| OIDC authentication | Built-in | Build (2 days) |
| OPA policies | No | Yes, full control |
| Policy standard | Custom (AWS IAM-inspired) | OPA (open standard) |
| RBAC path-level policies | Yes | Yes |
| ABAC / complex rules | No | Yes |
| URL scheme change | Yes (repo/branch/path) | No (transparent) |
| Presigned URL support | Yes (own scheme) | Hard |
| Versioning | Mandatory | None |
| PostgreSQL dependency | Yes | No |
| Time to MVP | Days | 4–6 weeks |
| Long-term maintenance | Upstream | You |

---

## Recommendation

**Start with LakeFS CE.** The built-in IAM-style policy engine covers the majority of real-world access control requirements (user/group can read/write path prefix). OIDC authentication is production-ready. The time-to-value is days, and the maintenance burden falls on upstream.

**Migrate to a custom proxy if and when:**
- Policy requirements emerge that cannot be expressed in LakeFS's engine (e.g., attribute-based rules derived from OIDC claims or object metadata)
- OPA is required as the single source of truth for authorization across the platform — LakeFS CE cannot participate in that model due to its non-standard, non-portable policy engine
- The repo/branch URL scheme causes unacceptable friction with existing tooling

At that point, the OPA evaluation logic itself is the easy part of the custom proxy — the engineering investment is in S3 wire compatibility and presigned URL handling. Scoping out presigned URLs for the initial version reduces the MVP estimate to 4–6 weeks.

---

## Consequences

- All S3 clients must be configured to point at the LakeFS endpoint instead of EU cloud S3 directly
- Storage layout adopts LakeFS's repository/branch model — teams need onboarding on this
- EU cloud S3 service account credentials are held only by LakeFS, never distributed to clients
- A PostgreSQL instance is required as part of the platform infrastructure
- If LakeFS Enterprise features (OPA integration, SSO enforcement) are needed in future, a commercial agreement is required
