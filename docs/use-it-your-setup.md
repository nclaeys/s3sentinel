# Use it in your setup

This guide walks you through the steps to set up s3sentinel in your environment.

## Create your object Storage credentials

### Find your endpoint and region

In the OVH Control Panel, go to **Public Cloud → Object Storage → your container** and note:

- **Region** — shown in the container list (e.g. `GRA`, `SBG`, `WAW`). The proxy uses the lowercase form: `gra`, `sbg`, `waw`.
- **Endpoint** — the S3-compatible URL for that region:

### Create S3 credentials

The proxy uses a single service-account key pair with full bucket access. Clients never see it.
When using OVH, you can get the credentials as follows:

1. In the OVH Control Panel open **Public Cloud → Users & Roles → Users**.
2. Create a user (or use an existing one) with the **ObjectStore operator** role.
3. Click the user → **S3 credentials** tab → **Generate credentials**.
4. Save the **Access key** and **Secret key** — they are shown only once.


## Create your OPA policies

OPA runs as a separate component and contains the policies for deciding whether a request is allowed or not.
S3sentinel calls OPA for every request before forwarding the request to the S3 compatible backend.

### Policy input format

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

### Create a policy

S3sentinel does not include any built-in policies, so you must write your own to get started.
Take a look at the [OPA documentation](https://www.openpolicyagent.org/docs/latest/policy-language/) and the example policy in `examples/basic/policy/reader-admin-policy.rego.

### Test your policy

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

## Deploy the s3sentinel proxy

Deploy the s3sentinel in your environment, using your favorite deployment method (Docker, Kubernetes, etc.).