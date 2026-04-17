package s3

import (
	"net/http"
	"net/url"
	"strings"
)

type Action string

const (
	ActionListBuckets Action = "ListBuckets"
)

const (
	ActionHeadBucket           Action = "HeadBucket"
	ActionCreateBucket         Action = "CreateBucket"
	ActionDeleteBucket         Action = "DeleteBucket"
	ActionListObjects          Action = "ListObjects"
	ActionListObjectsV2        Action = "ListObjectsV2"
	ActionGetBucketAcl         Action = "GetBucketAcl"
	ActionPutBucketAcl         Action = "PutBucketAcl"
	ActionGetBucketLocation    Action = "GetBucketLocation"
	ActionGetBucketVersioning  Action = "GetBucketVersioning"
	ActionPutBucketVersioning  Action = "PutBucketVersioning"
	ActionGetBucketCors        Action = "GetBucketCors"
	ActionPutBucketCors        Action = "PutBucketCors"
	ActionDeleteBucketCors     Action = "DeleteBucketCors"
	ActionListMultipartUploads Action = "ListMultipartUploads"
	ActionDeleteObjects        Action = "DeleteObjects" // POST /bucket?delete
)

const (
	ActionGetObject               Action = "GetObject"
	ActionHeadObject              Action = "HeadObject"
	ActionPutObject               Action = "PutObject"
	ActionDeleteObject            Action = "DeleteObject"
	ActionCopyObject              Action = "CopyObject"
	ActionGetObjectAcl            Action = "GetObjectAcl"
	ActionPutObjectAcl            Action = "PutObjectAcl"
	ActionGetObjectTagging        Action = "GetObjectTagging"
	ActionPutObjectTagging        Action = "PutObjectTagging"
	ActionDeleteObjectTagging     Action = "DeleteObjectTagging"
	ActionCreateMultipartUpload   Action = "CreateMultipartUpload"
	ActionUploadPart              Action = "UploadPart"
	ActionCompleteMultipartUpload Action = "CompleteMultipartUpload"
	ActionAbortMultipartUpload    Action = "AbortMultipartUpload"
	ActionListParts               Action = "ListParts"

	ActionUnknown Action = "Unknown"
)

type S3RequestContext struct {
	Action Action
	Bucket string
	Key    string
}

func Parse(r *http.Request, proxyHost string) S3RequestContext {
	bucket, key := ExtractBucketAndKey(r, proxyHost)

	q := r.URL.Query()
	method := r.Method

	if bucket == "" {
		if method == http.MethodGet {
			return S3RequestContext{Action: ActionListBuckets}
		}
		return S3RequestContext{Action: ActionUnknown}
	}

	if key != "" {
		return parseObjectAction(r, method, q, bucket, key)
	}

	return parseBucketAction(method, q, bucket)
}

func parseBucketAction(method string, q url.Values, bucket string) S3RequestContext {
	pr := S3RequestContext{Bucket: bucket}

	switch method {
	case http.MethodHead:
		pr.Action = ActionHeadBucket

	case http.MethodPut:
		switch {
		case q.Has("acl"):
			pr.Action = ActionPutBucketAcl
		case q.Has("versioning"):
			pr.Action = ActionPutBucketVersioning
		case q.Has("cors"):
			pr.Action = ActionPutBucketCors
		default:
			pr.Action = ActionCreateBucket
		}

	case http.MethodDelete:
		switch {
		case q.Has("cors"):
			pr.Action = ActionDeleteBucketCors
		default:
			pr.Action = ActionDeleteBucket
		}

	case http.MethodPost:
		if q.Has("delete") {
			pr.Action = ActionDeleteObjects
		} else {
			pr.Action = ActionUnknown
		}

	case http.MethodGet:
		switch {
		case q.Has("acl"):
			pr.Action = ActionGetBucketAcl
		case q.Has("location"):
			pr.Action = ActionGetBucketLocation
		case q.Has("versioning"):
			pr.Action = ActionGetBucketVersioning
		case q.Has("cors"):
			pr.Action = ActionGetBucketCors
		case q.Has("uploads"):
			pr.Action = ActionListMultipartUploads
		case q.Get("list-type") == "2":
			pr.Action = ActionListObjectsV2
		default:
			pr.Action = ActionListObjects
		}

	default:
		pr.Action = ActionUnknown
	}

	return pr
}

func parseObjectAction(r *http.Request, method string, q url.Values, bucket, key string) S3RequestContext {
	pr := S3RequestContext{Bucket: bucket, Key: key}

	switch method {
	case http.MethodGet:
		switch {
		case q.Has("acl"):
			pr.Action = ActionGetObjectAcl
		case q.Has("tagging"):
			pr.Action = ActionGetObjectTagging
		case q.Has("uploadId") && !q.Has("partNumber"):
			pr.Action = ActionListParts
		default:
			pr.Action = ActionGetObject
		}

	case http.MethodHead:
		pr.Action = ActionHeadObject

	case http.MethodPut:
		switch {
		case q.Has("acl"):
			pr.Action = ActionPutObjectAcl
		case q.Has("tagging"):
			pr.Action = ActionPutObjectTagging
		case q.Has("partNumber"):
			pr.Action = ActionUploadPart
		case r.Header.Get("X-Amz-Copy-Source") != "":
			pr.Action = ActionCopyObject
		default:
			pr.Action = ActionPutObject
		}

	case http.MethodDelete:
		switch {
		case q.Has("tagging"):
			pr.Action = ActionDeleteObjectTagging
		case q.Has("uploadId"):
			pr.Action = ActionAbortMultipartUpload
		default:
			pr.Action = ActionDeleteObject
		}

	case http.MethodPost:
		switch {
		case q.Has("uploads"):
			pr.Action = ActionCreateMultipartUpload
		case q.Has("uploadId"):
			pr.Action = ActionCompleteMultipartUpload
		default:
			pr.Action = ActionUnknown
		}

	default:
		pr.Action = ActionUnknown
	}

	return pr
}

// ExtractBucketAndKey extracts the S3 bucket and object key from an HTTP request,
// supporting both addressing styles:
//   - Path-style: /bucket/key/path → bucket="bucket", key="key/path"
//   - Virtual-hosted-style: bucket.proxyHost/key → bucket="bucket", key="key"
func ExtractBucketAndKey(r *http.Request, proxyHost string) (bucket, key string) {
	host := r.Host
	if host == "" {
		host = r.URL.Host
	}
	if idx := strings.LastIndex(host, ":"); idx > strings.LastIndex(host, "]") {
		host = host[:idx]
	}

	if proxyHost != "" && strings.HasSuffix(host, "."+proxyHost) {
		bucket = strings.TrimSuffix(host, "."+proxyHost)
		key = strings.TrimPrefix(r.URL.Path, "/")
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/")
	parts := strings.SplitN(path, "/", 2)
	bucket = parts[0]
	if len(parts) == 2 {
		key = parts[1]
	}
	return
}
