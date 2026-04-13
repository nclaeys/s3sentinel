package s3

import rego.v1

# Deny everything by default.
default allow := false

# ── Example rules — replace with your own ──────────────────────────────────

# Admins can perform any operation on any bucket.
allow if {
    input.groups[_] == "admins"
}

# Data engineers can read from any bucket.
allow if {
    input.action in {
        "GetObject",
        "HeadObject",
        "ListObjects",
        "ListObjectsV2",
        "GetObjectTagging",
    }
    input.groups[_] == "data-engineers"
}

# Data engineers can write only to the raw/ prefix.
allow if {
    input.action in {
        "PutObject",
        "DeleteObject",
        "CopyObject",
        "PutObjectTagging",
        "DeleteObjectTagging",
        "CreateMultipartUpload",
        "UploadPart",
        "CompleteMultipartUpload",
        "AbortMultipartUpload",
    }
    input.groups[_] == "data-engineers"
    startswith(input.key, "raw/")
}

# Anyone can list their own bucket (bucket name equals their principal).
allow if {
    input.action in {"HeadBucket", "ListObjects", "ListObjectsV2"}
    input.bucket == input.principal
}
