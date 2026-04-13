package s3

import rego.v1

# Deny everything by default.
default allow := false

# Admins can perform any operation on any bucket.
allow if {
    input.groups[_] == "admin"
}

# Readers can list buckets and read objects.
allow if {
    input.groups[_] == "reader"
    input.action in {
        "ListBuckets",
        "HeadBucket",
        "ListObjects",
        "ListObjectsV2",
        "HeadObject",
        "GetObject",
        "GetObjectTagging",
    }
}
